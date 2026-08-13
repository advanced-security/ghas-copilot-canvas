// Extension: code-quality-enablement
// Enable/disable GitHub Code Quality across every organization in an enterprise.
//
// GitHub Code Quality (public preview) only exposes a *repository-level* REST API
// (`GET`/`PATCH /repos/{owner}/{repo}/code-quality/setup`). The organization-wide
// "Repository access" toggle shown in org Settings > Security > Code quality has
// no public API yet. This extension gives you an org-level UX (checkbox table,
// enable-all/disable-all, per-org toggle) and implements the effect server-side by
// paginating every repo in the selected org(s) and calling the repo-level API in
// the background, so the UI never has to render a 10k-row repo table.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, normalize } from "node:path";
import { randomUUID } from "node:crypto";
import { CanvasError, createCanvas, joinSession } from "@github/copilot-sdk/extension";
import { createDiagnosticLog } from "./diagnostics.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = resolve(__dirname, "public");

const API_VERSION = "2026-03-10";
const STATUS_SAMPLE_SIZE = 40; // repos sampled per org when computing a quick status
const CONCURRENCY = 6; // parallel repo API calls when scanning (read-only, handles concurrency fine)

// PATCH concurrency was never actually the cause of the "malformed request" 400s seen
// during bulk toggles (root cause was a broken stdin write in execGh, see execGh's
// comment above) - but keeping mutating writes modestly serialized is still reasonable
// since it's a write path, not a read path.
const TOGGLE_CONCURRENCY = 4;

// In-memory, redacted log of every `gh` invocation this canvas makes, shown as
// an "API activity" tail at the bottom of the UI. Bounded (oldest entries are
// evicted), never persisted, and cleared when this process exits.
const diagnosticLog = createDiagnosticLog();
diagnosticLog.add({
  source: "canvas",
  operation: "Diagnostic log initialized",
  message: "Activity is held in memory, bounded to 100 entries, and cleared when this canvas closes.",
});

// --- gh helpers -------------------------------------------------------------
//
// A `GH_TOKEN`/`GITHUB_TOKEN` env var (if present) takes precedence over gh's
// stored keyring login, and may carry fewer scopes than this extension needs
// (read:enterprise/read:org for listing orgs, repo for code-quality PATCH).
// `authMode` lets the user pick which identity gh should use:
//   "auto"    - use env token if set, but auto-retry once with it stripped if
//               a call fails with an auth/scope error (silent recovery).
//   "env"     - always use the env token (never strip it).
//   "keyring" - always strip env tokens so gh falls back to its keyring login.
let authMode = "auto";

function looksLikeAuthScopeIssue(msg) {
  const blob = (msg || "").toLowerCase();
  return /http 401|http 403|requires? .*scope|needs the .* scope|must have admin|bad credentials|requires authentication|insufficient_scopes/.test(blob);
}

// NOTE: Node's async child_process.execFile (and promisify(execFile)) does NOT
// support an `input` option to write to the child's stdin - that only exists on
// the *Sync variants (execFileSync/spawnSync). Passing `{ input }` to the async
// exec/execFile is silently ignored, leaving `gh api ... --input -` reading a
// stdin pipe that's never written to or closed. `gh`/GitHub's edge then hangs
// for ~10s before rejecting the request with a generic, misleading "malformed
// request" 400 - even though the exact same call succeeds instantly when run
// manually (where the shell wires up stdin correctly). Use spawn() and write to
// child.stdin ourselves so the body is actually sent and stdin is closed (EOF).
async function execGh(args, { input, stripTokens = false } = {}) {
  const env = { ...process.env, GH_PROMPT_DISABLED: "1" };
  if (stripTokens) {
    delete env.GH_TOKEN;
    delete env.GITHUB_TOKEN;
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn("gh", args, { env, windowsHide: true });
    const stdoutChunks = [];
    const stderrChunks = [];
    let settled = false;
    child.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    child.stderr.on("data", (chunk) => stderrChunks.push(chunk));
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      rejectPromise(err);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      const stdout = Buffer.concat(stdoutChunks).toString();
      const stderr = Buffer.concat(stderrChunks).toString();
      if (code === 0) {
        resolvePromise({ stdout, stderr });
      } else {
        const err = new Error(stderr || stdout || `gh exited with code ${code}`);
        err.stdout = stdout;
        err.stderr = stderr;
        err.code = code;
        rejectPromise(err);
      }
    });
    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

// Classifies a `gh` invocation for the diagnostic log so entries read like
// "GET /repos/o/r/code-quality/setup" rather than a raw argv dump.
function summarizeGhArgs(args) {
  if (args[0] === "api" && args[1] === "graphql") {
    return { source: "github-graphql", operation: "POST /graphql" };
  }
  const xIdx = args.indexOf("-X");
  const method = xIdx >= 0 ? args[xIdx + 1] : null;
  const path = args.find((a) => typeof a === "string" && a.startsWith("/"));
  if (method && path) return { source: "github-api", operation: `${method} ${path}` };
  return { source: "gh-cli", operation: args.slice(0, 3).join(" ") };
}

function previewGhOutput(stdout) {
  const text = (stdout || "").toString();
  try { return JSON.parse(text); } catch { return text; }
}

// A handful of PATCH rejections are expected/deterministic outcomes that the
// callers above `gh()` already classify and handle gracefully (skipped, not a
// real failure) - e.g. trying to enable AI findings before Code Quality itself
// is configured, or an org/enterprise policy blocking a change. Log these as
// "warning" rather than "error" so the diagnostics log doesn't read as if
// every one of these expected, already-handled rejections were a real bug.
//
// Note: the "while code quality is disabled" 422 is currently also hit for
// repos where Code Quality *was just* configured but the initial CodeQL scan
// hasn't finished yet - GitHub doesn't allow enabling AI findings until that
// first scan completes. This is a known product bug (not by design) that
// GitHub expects to fix, at which point AI findings should be enable-able
// immediately after configuring Code Quality. Until then we just skip/retry
// via the bulk-toggle "skipped: requires-quality" path rather than erroring.
const EXPECTED_REJECTION_MSG = /while code quality is disabled|organization or enterprise policy prevents/i;

async function gh(args, { input } = {}) {
  const stripFirst = authMode === "keyring";
  const startedAt = Date.now();
  const { operation, source } = summarizeGhArgs(args);
  const request = { args, ...(input !== undefined ? { input } : {}) };
  try {
    const { stdout } = await execGh(args, { input, stripTokens: stripFirst });
    diagnosticLog.add({
      level: "info",
      source,
      operation,
      durationMs: Date.now() - startedAt,
      request,
      response: { body: previewGhOutput(stdout) },
    });
    return stdout;
  } catch (err) {
    const stderr = (err.stderr || "").toString().trim();
    const stdout = (err.stdout || "").toString().trim();
    const msg = stderr || stdout || err.message || "gh command failed";
    // In "auto" mode, retry once with env tokens stripped if this looks like
    // an auth/scope wall caused by a limited env token shadowing a better
    // keyring login.
    if (authMode === "auto" && !stripFirst && looksLikeAuthScopeIssue(msg)) {
      try {
        const { stdout: retryOut } = await execGh(args, { input, stripTokens: true });
        diagnosticLog.add({
          level: "warning",
          source,
          operation,
          durationMs: Date.now() - startedAt,
          message: "Retried with env tokens stripped after an auth/scope error on the first attempt.",
          request,
          response: { body: previewGhOutput(retryOut) },
        });
        return retryOut;
      } catch {
        // fall through to the original error below
      }
    }
    diagnosticLog.add({
      level: EXPECTED_REJECTION_MSG.test(msg) ? "warning" : "error",
      source,
      operation,
      durationMs: Date.now() - startedAt,
      request,
      error: { message: msg },
    });
    const e = new Error(msg);
    e.code = "gh_error";
    throw e;
  }
}

// Probe both identities (env token and keyring token) so the UI can show
// "Signed in as" + scopes and let the user pick which one to use.
async function getAuthStatus() {
  async function probe(stripTokens) {
    try {
      const { stdout } = await execGh(
        ["api", "-i", "-H", "Accept: application/vnd.github+json", "/user"],
        { stripTokens }
      );
      const headerEnd = stdout.indexOf("\r\n\r\n");
      const rawHeaders = headerEnd >= 0 ? stdout.slice(0, headerEnd) : "";
      const body = headerEnd >= 0 ? stdout.slice(headerEnd + 4) : stdout;
      const scopesLine = rawHeaders.split("\n").find((l) => /^x-oauth-scopes:/i.test(l.trim()));
      const scopes = scopesLine
        ? scopesLine.split(":").slice(1).join(":").split(",").map((s) => s.trim()).filter(Boolean)
        : [];
      const data = JSON.parse(body);
      return { available: true, login: data.login, name: data.name, scopes };
    } catch (err) {
      return { available: false, error: (err.stderr || err.message || "").toString().trim() };
    }
  }

  const envHasToken = !!(process.env.GH_TOKEN || process.env.GITHUB_TOKEN);
  const [asIs, keyring] = await Promise.all([probe(false), probe(true)]);
  // "env" identity is only meaningful/distinct if an env token is actually set.
  const env = envHasToken ? asIs : null;
  // If no env token is set, the "as-is" probe already reflects the keyring login.
  const effectiveKeyring = envHasToken ? keyring : asIs;

  return {
    mode: authMode,
    envToken: env,
    keyring: effectiveKeyring,
    // Whichever identity gh would actually use right now, given authMode.
    active: authMode === "keyring" || !envHasToken ? effectiveKeyring : env,
  };
}

async function ghJson(args, opts) {
  const out = await gh(args, opts);
  if (!out.trim()) return null;
  try { return JSON.parse(out); } catch { return out; }
}

async function ghApi(path, { method = "GET", rawBody } = {}) {
  const args = [
    "api", "-X", method, path,
    "-H", "Accept: application/vnd.github+json",
    "-H", `X-GitHub-Api-Version: ${API_VERSION}`,
  ];
  if (rawBody !== undefined) {
    args.push("--input", "-");
    return ghJson(args, { input: rawBody });
  }
  return ghJson(args);
}

async function ghGraphQL(query, variables = {}) {
  const args = ["api", "graphql", "-f", `query=${query}`];
  for (const [k, v] of Object.entries(variables)) {
    if (v === undefined || v === null) continue;
    args.push("-F", `${k}=${v}`);
  }
  const data = await ghJson(args);
  if (data?.errors?.length) {
    const e = new Error(data.errors.map((x) => x.message).join("; "));
    e.code = "graphql_error";
    throw e;
  }
  return data?.data;
}

async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, run);
  await Promise.all(workers);
  return results;
}

// --- Enterprise / org discovery ---------------------------------------------

const ENTERPRISE_ORGS_QUERY = `
query($slug: String!, $cursor: String) {
  enterprise(slug: $slug) {
    slug
    name
    organizations(first: 50, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      totalCount
      nodes {
        login
        name
        avatarUrl
        url
        repositories { totalCount }
      }
    }
  }
}`;

async function listEnterpriseOrgs(enterprise, { maxPages = 40 } = {}) {
  if (!enterprise) throw new CanvasError("missing_enterprise", "enterprise slug is required");
  const orgs = [];
  let cursor;
  let pages = 0;
  let enterpriseName = enterprise;
  let truncated = false;
  do {
    const data = await ghGraphQL(ENTERPRISE_ORGS_QUERY, { slug: enterprise, cursor });
    const ent = data?.enterprise;
    if (!ent) throw new CanvasError("enterprise_not_found", `Enterprise '${enterprise}' not found or not accessible`);
    enterpriseName = ent.name || ent.slug;
    for (const n of ent.organizations.nodes) {
      orgs.push({
        login: n.login,
        name: n.name,
        avatarUrl: n.avatarUrl,
        htmlUrl: n.url,
        repoCount: n.repositories?.totalCount ?? null,
      });
    }
    cursor = ent.organizations.pageInfo.hasNextPage ? ent.organizations.pageInfo.endCursor : null;
    pages++;
    if (cursor && pages >= maxPages) { truncated = true; break; }
  } while (cursor);
  orgs.sort((a, b) => a.login.localeCompare(b.login));
  return { enterprise: enterpriseName, slug: enterprise, orgs, truncated };
}

// --- Repo listing -------------------------------------------------------------

// Streams NDJSON (one JSON object per line) across every page so we never hold
// a giant concatenated JSON array in memory for huge orgs.
async function listOrgRepos(org, { type = "sources" } = {}) {
  const out = await gh([
    "api", "-X", "GET", "--paginate", `/orgs/${org}/repos`,
    "-f", "per_page=100",
    "-f", `type=${type}`,
    "-H", `X-GitHub-Api-Version: ${API_VERSION}`,
    "--jq", ".[] | {name: .name, full_name: .full_name, archived: .archived, disabled: .disabled, fork: .fork, language: .language, topics: .topics}",
  ]);
  return out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// Matches a repo against a simple filter spec used by the "Matching a filter"
// bulk-toggle mode. All provided criteria must match (AND). Each criterion is
// case-insensitive; `namePattern` is a substring match against the repo name.
function repoMatchesFilter(repo, filter) {
  if (!filter) return true;
  const { namePattern, language, topic } = filter;
  if (namePattern && !repo.name.toLowerCase().includes(String(namePattern).toLowerCase())) return false;
  if (language && String(repo.language || "").toLowerCase() !== String(language).toLowerCase()) return false;
  if (topic && !(repo.topics || []).some((t) => t.toLowerCase() === String(topic).toLowerCase())) return false;
  return true;
}

// Trims a raw filter payload down to only the recognized, non-empty criteria.
function normalizeFilter(raw) {
  if (!raw || typeof raw !== "object") return null;
  const filter = {};
  for (const key of ["namePattern", "language", "topic"]) {
    if (typeof raw[key] === "string" && raw[key].trim()) filter[key] = raw[key].trim();
  }
  return Object.keys(filter).length ? filter : null;
}

// --- Code quality setup (repo-level) ----------------------------------------

async function getCodeQualitySetup(owner, repo) {
  try {
    const data = await ghApi(`/repos/${owner}/${repo}/code-quality/setup`);
    // ai_findings_option is "on_push" when AI-based findings are enabled, or
    // "disabled" (or absent) otherwise. It's a separate feature from the main
    // CodeQL-based "state" toggle, and can only be turned on while state is
    // "configured" - GitHub returns a 422 if you try to enable it otherwise.
    //
    // A repo can be "configured" for Code Quality yet still be ineligible for
    // AI findings specifically: if none of the repo's languages are supported,
    // GitHub reports `languages: []` and `ai_findings_option: null` (a literal
    // null, not the string "disabled"), and a PATCH to enable it is silently a
    // no-op (200 response with run_id: 0 - no scan ever runs, the field never
    // flips). Treat that combination as not-eligible rather than "off", so bulk
    // AI-toggle status doesn't misreport these repos as failed/off.
    const aiEligible = Array.isArray(data?.languages) && data.languages.length > 0;
    return {
      state: data?.state || "not-configured",
      aiFindings: data?.ai_findings_option === "on_push",
      aiEligible,
      ok: true,
    };
  } catch (err) {
    // 404/403 => code quality isn't available for this repo (unsupported language,
    // feature not allowed, archived, etc). Surface as "not-eligible" rather than error.
    if (/404|403/.test(err.message)) return { state: "not-eligible", aiFindings: false, aiEligible: false, ok: true };
    return { state: "error", aiFindings: false, aiEligible: false, ok: false, error: err.message };
  }
}

// GitHub's org/enterprise policy for Code Quality only blocks *changing* the
// setting - an idempotent PATCH to the same value the repo already has succeeds
// even when policy would block a real change. That means we can only detect a
// policy block by actually attempting the desired change (see setCodeQualitySetup
// below); there is no side-effect-free way to know ahead of time during a
// passive status check.
const POLICY_BLOCKED_MSG = /organization or enterprise policy prevents/i;

// A handful of PATCH failures are transient rather than real rejections: the
// documented 409 ("already a code quality setup configuration update in
// progress") and 503, plus an *undocumented* 400 "malformed request from your
// client" that GitHub's edge occasionally returns for this endpoint and which
// - per observation - succeeds immediately on retry with the exact same
// request/body. Retry a few times with a short backoff before surfacing these
// as real failures, so a transient hiccup during a large bulk-toggle doesn't
// get reported to the user as a permanent per-repo error.
const TRANSIENT_MSG = /already .*code quality setup configuration update in progress|http 409|http 503|service unavailable|malformed request from your client/i;

async function withTransientRetry(fn, { attempts = 3, delayMs = 700 } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt >= attempts || !TRANSIENT_MSG.test(err.message)) throw err;
      await new Promise((r) => setTimeout(r, delayMs * attempt));
    }
  }
  throw lastErr;
}

async function setCodeQualitySetup(owner, repo, enable) {
  const body = JSON.stringify({ state: enable ? "configured" : "not-configured" });
  try {
    await withTransientRetry(() =>
      ghApi(`/repos/${owner}/${repo}/code-quality/setup`, { method: "PATCH", rawBody: body })
    );
    return { ok: true };
  } catch (err) {
    if (POLICY_BLOCKED_MSG.test(err.message)) return { ok: true, skipped: true, reason: "policy-blocked" };
    if (/404|403/.test(err.message)) return { ok: true, skipped: true, reason: "not-eligible" };
    return { ok: false, error: err.message };
  }
}

// AI-based findings ("Scans" under the "AI findings" section of a repo's Code
// quality settings page) are a separate on/off flag from the main CodeQL-based
// "state". GitHub requires state to already be "configured" before it will let
// you turn ai_findings_option on - trying to enable it on a repo where Code
// Quality itself is off/not-configured returns a 422 with a distinct message.
const AI_REQUIRES_QUALITY_MSG = /while code quality is disabled/i;

async function setAiFindings(owner, repo, enable) {
  const body = JSON.stringify({ ai_findings_option: enable ? "on_push" : "disabled" });
  try {
    // AI findings can only be enabled once Code Quality's own "state: configured"
    // PATCH has fully settled on GitHub's side, which can still be in flight for
    // a few seconds after that call returns 200 (e.g. right after a bulk
    // "Enable all" quality run immediately followed by an AI-enable run). That
    // window surfaces as repeated 409 "Configuration update already in
    // progress" - give this call a longer/more patient retry budget than the
    // default so a fast follow-up toggle doesn't spuriously fail.
    const res = await withTransientRetry(
      () => ghApi(`/repos/${owner}/${repo}/code-quality/setup`, { method: "PATCH", rawBody: body }),
      { attempts: 6, delayMs: 1000 }
    );
    // GitHub always returns 200 for this PATCH, even for repos with no
    // AI-findings-eligible language: in that case it returns `run_id: 0` /
    // `run_url: ""` and never actually runs a scan, so ai_findings_option
    // silently never flips. Treat that as skipped/not-eligible instead of a
    // real success, so bulk-toggle results (and the resulting badge) reflect
    // reality rather than reporting every PATCH as "succeeded".
    if (enable && res && res.run_id === 0) return { ok: true, skipped: true, reason: "not-eligible" };
    return { ok: true };
  } catch (err) {
    if (AI_REQUIRES_QUALITY_MSG.test(err.message)) return { ok: true, skipped: true, reason: "requires-quality" };
    if (POLICY_BLOCKED_MSG.test(err.message)) return { ok: true, skipped: true, reason: "policy-blocked" };
    if (/404|403/.test(err.message)) return { ok: true, skipped: true, reason: "not-eligible" };
    return { ok: false, error: err.message };
  }
}

// --- Quick sampled status for an org -----------------------------------------

async function sampleOrgStatus(org, sampleSize = STATUS_SAMPLE_SIZE) {
  const all = await listOrgRepos(org);
  const eligible = all.filter((r) => !r.archived && !r.disabled);
  const sample = eligible.slice(0, sampleSize);
  const results = await pool(sample, CONCURRENCY, async (r) => {
    const res = await getCodeQualitySetup(org, r.name);
    return { repo: r.name, ...res };
  });
  const counts = { configured: 0, "not-configured": 0, "not-eligible": 0, error: 0 };
  for (const r of results) counts[r.state] = (counts[r.state] || 0) + 1;
  const checkable = counts.configured + counts["not-configured"];
  let overall = "unknown";
  if (checkable > 0) {
    if (counts.configured === checkable) overall = "enabled";
    else if (counts["not-configured"] === checkable) overall = "disabled";
    else overall = "partial";
  } else if (counts["not-eligible"] > 0) {
    overall = "not-eligible";
  }

  // AI findings can only meaningfully be "on"/"off" for repos where Code
  // Quality is configured AND the repo has at least one AI-findings-eligible
  // language (languages: [] means GitHub silently no-ops AI-findings PATCHes
  // for this repo - see getCodeQualitySetup). Everything else is "n/a".
  const aiCounts = { on: 0, off: 0, "n/a": 0, error: 0 };
  for (const r of results) {
    if (r.state === "error") aiCounts.error++;
    else if (r.state === "configured" && r.aiEligible) aiCounts[r.aiFindings ? "on" : "off"]++;
    else aiCounts["n/a"]++;
  }
  const aiCheckable = aiCounts.on + aiCounts.off;
  let aiOverall = "unknown";
  if (aiCheckable > 0) {
    if (aiCounts.on === aiCheckable) aiOverall = "enabled";
    else if (aiCounts.off === aiCheckable) aiOverall = "disabled";
    else aiOverall = "partial";
  } else if (aiCounts["n/a"] > 0) {
    aiOverall = "not-eligible";
  }

  return {
    org,
    totalRepos: all.length,
    sampledRepos: sample.length,
    counts,
    overall,
    aiCounts,
    aiOverall,
    sampled: sample.length < eligible.length,
  };
}

// --- Bulk enable/disable jobs -------------------------------------------------

const jobs = new Map();

function newJob(orgLogins) {
  const id = randomUUID();
  const job = {
    id,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    cancelled: false,
    orgs: Object.fromEntries(orgLogins.map((login) => [login, {
      login, status: "queued", total: 0, done: 0, succeeded: 0, failed: 0, skipped: 0, policyBlocked: 0, requiresQuality: 0, errors: [],
    }])),
  };
  jobs.set(id, job);
  return job;
}

async function runOrgToggle(job, login, enable, filter, target = "quality") {
  const orgState = job.orgs[login];
  orgState.status = "listing-repos";
  let repos;
  try {
    repos = (await listOrgRepos(login)).filter((r) => !r.archived && !r.disabled);
    if (filter) repos = repos.filter((r) => repoMatchesFilter(r, filter));
  } catch (err) {
    orgState.status = "failed";
    orgState.errors.push(`Failed to list repos: ${err.message}`);
    return;
  }
  orgState.total = repos.length;
  orgState.status = "applying";
  const setter = target === "ai" ? setAiFindings : setCodeQualitySetup;
  await pool(repos, TOGGLE_CONCURRENCY, async (r) => {
    if (job.cancelled) return;
    const res = await setter(login, r.name, enable);
    if (res.ok && !res.skipped) orgState.succeeded++;
    else if (res.skipped) {
      orgState.skipped++;
      if (res.reason === "policy-blocked") orgState.policyBlocked++;
      if (res.reason === "requires-quality") orgState.requiresQuality++;
    } else {
      orgState.failed++;
      if (orgState.errors.length < 20) orgState.errors.push(`${r.name}: ${res.error}`);
    }
    orgState.done++;
  });
  orgState.status = job.cancelled ? "cancelled" : "done";
}

async function startBulkToggle(orgLogins, enable, filter, target = "quality") {
  const job = newJob(orgLogins);
  job.filter = filter || null;
  job.target = target;
  // Run orgs with limited concurrency too, so we don't fan out unboundedly across
  // many large orgs at once.
  (async () => {
    await pool(orgLogins, 3, (login) => runOrgToggle(job, login, enable, filter, target));
    job.finishedAt = new Date().toISOString();
  })();
  return job;
}

function jobSnapshot(job) {
  const orgs = Object.values(job.orgs);
  const finished = orgs.every((o) => ["done", "failed", "cancelled"].includes(o.status));
  return {
    id: job.id,
    startedAt: job.startedAt,
    finishedAt: finished ? (job.finishedAt || new Date().toISOString()) : null,
    cancelled: job.cancelled,
    filter: job.filter || null,
    target: job.target || "quality",
    orgs,
  };
}

// --- HTTP server for iframe -------------------------------------------------

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(data),
    "Cache-Control": "no-store",
  });
  res.end(data);
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return {}; }
}

async function serveStatic(_req, res, pathname) {
  const rel = pathname === "/" ? "/index.html" : pathname;
  const safe = normalize(rel).replace(/^([\\/]+)/, "");
  const full = join(PUBLIC_DIR, safe);
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403).end(); return; }
  try {
    const data = await readFile(full);
    const ext = full.slice(full.lastIndexOf(".")).toLowerCase();
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Content-Length": data.length,
      "Cache-Control": "no-store",
    });
    res.end(data);
  } catch {
    res.writeHead(404).end("Not found");
  }
}

function startServer() {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      const p = url.pathname;

      if (p.startsWith("/api/")) {
        if (req.method === "GET" && p === "/api/whoami") {
          try {
            const me = await ghApi("/user");
            return sendJson(res, 200, { login: me.login, name: me.name });
          } catch (err) {
            return sendJson(res, 200, { login: null, error: err.message });
          }
        }
        if (req.method === "GET" && p === "/api/auth") {
          return sendJson(res, 200, await getAuthStatus());
        }
        if (req.method === "POST" && p === "/api/auth") {
          const body = await readJsonBody(req);
          if (!["auto", "env", "keyring"].includes(body.mode)) {
            throw new CanvasError("bad_mode", "mode must be one of auto, env, keyring");
          }
          authMode = body.mode;
          return sendJson(res, 200, await getAuthStatus());
        }
        if (req.method === "GET" && p === "/api/orgs") {
          const enterprise = url.searchParams.get("enterprise");
          return sendJson(res, 200, await listEnterpriseOrgs(enterprise));
        }
        if (req.method === "GET" && p === "/api/org-status") {
          const org = url.searchParams.get("org");
          if (!org) throw new CanvasError("missing_org", "org is required");
          return sendJson(res, 200, await sampleOrgStatus(org));
        }
        if (req.method === "POST" && p === "/api/bulk-toggle") {
          const body = await readJsonBody(req);
          const orgs = Array.isArray(body.orgs) ? body.orgs.filter(Boolean) : [];
          if (!orgs.length) throw new CanvasError("missing_orgs", "orgs[] is required");
          const filter = normalizeFilter(body.filter);
          const target = body.target === "ai" ? "ai" : "quality";
          const job = await startBulkToggle(orgs, !!body.enable, filter, target);
          return sendJson(res, 200, jobSnapshot(job));
        }
        if (req.method === "GET" && p === "/api/job") {
          const id = url.searchParams.get("id");
          const job = jobs.get(id);
          if (!job) return sendJson(res, 404, { error: "job not found" });
          return sendJson(res, 200, jobSnapshot(job));
        }
        if (req.method === "POST" && p === "/api/cancel-job") {
          const body = await readJsonBody(req);
          const job = jobs.get(body.id);
          if (!job) return sendJson(res, 404, { error: "job not found" });
          job.cancelled = true;
          return sendJson(res, 200, jobSnapshot(job));
        }
        if (req.method === "GET" && p === "/api/logs") {
          const after = url.searchParams.get("after");
          return sendJson(res, 200, diagnosticLog.snapshot(after));
        }
        if (req.method === "DELETE" && p === "/api/logs") {
          return sendJson(res, 200, diagnosticLog.clear());
        }
        return sendJson(res, 404, { error: "Not found" });
      }

      if (req.method === "GET") return serveStatic(req, res, p);
      res.writeHead(405).end();
    } catch (err) {
      const code = err.code === "gh_error" ? 502 : err.code ? 400 : 500;
      if (!req.url?.startsWith("/api/logs")) {
        diagnosticLog.add({
          level: "error",
          source: "canvas",
          operation: `${req.method} ${req.url}`,
          error: { message: err.message, code: err.code },
        });
      }
      sendJson(res, code, { error: err.message, code: err.code });
    }
  });

  return new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", () => {
      resolveListen({ server, port: server.address().port });
    });
  });
}

// --- Canvas declaration -----------------------------------------------------

let serverInfo;

const canvas = createCanvas({
  id: "code-quality-enablement",
  displayName: "Code Quality Enablement",
  description:
    "Bulk enable/disable GitHub Code Quality across every organization in an enterprise. Lists orgs in a checkbox table (not repos - orgs can have 10k+ repos), shows a sampled enablement status per org, and lets you enable-all / disable-all selected orgs or toggle a single org; the toggle is applied by paginating and updating every repo in the org(s) in the background via the repo-level code-quality/setup API.",
  inputSchema: {
    type: "object",
    properties: {
      enterprise: { type: "string", description: "Enterprise slug to pre-load orgs for" },
    },
    additionalProperties: false,
  },
  actions: [
    {
      name: "list_enterprise_orgs",
      description: "List all organizations in a GitHub Enterprise, with repo counts.",
      inputSchema: {
        type: "object",
        required: ["enterprise"],
        properties: { enterprise: { type: "string" } },
      },
      async handler({ input }) { return listEnterpriseOrgs(input.enterprise); },
    },
    {
      name: "get_auth_status",
      description: "Show which GitHub identity (env token vs. keyring login) gh is currently using, and its scopes.",
      inputSchema: { type: "object", properties: {} },
      async handler() { return getAuthStatus(); },
    },
    {
      name: "set_auth_mode",
      description: "Choose which GitHub identity gh should use: 'auto' (env token, falling back to keyring on scope errors), 'env' (always the env token), or 'keyring' (always the stored gh login, ignoring env tokens).",
      inputSchema: {
        type: "object",
        required: ["mode"],
        properties: { mode: { type: "string", enum: ["auto", "env", "keyring"] } },
      },
      async handler({ input }) {
        authMode = input.mode;
        return getAuthStatus();
      },
    },
    {
      name: "get_org_status",
      description: "Get a sampled GitHub Code Quality enablement status for one organization (enabled/disabled/partial/not-eligible/unknown).",
      inputSchema: {
        type: "object",
        required: ["org"],
        properties: { org: { type: "string" } },
      },
      async handler({ input }) { return sampleOrgStatus(input.org); },
    },
    {
      name: "bulk_toggle_code_quality",
      description: "Enable or disable GitHub Code Quality for every repo in one or more organizations (runs in the background; returns a jobId to poll).",
      inputSchema: {
        type: "object",
        required: ["orgs", "enable"],
        properties: {
          orgs: { type: "array", items: { type: "string" } },
          enable: { type: "boolean" },
        },
      },
      async handler({ input }) {
        const job = await startBulkToggle(input.orgs, !!input.enable);
        return jobSnapshot(job);
      },
    },
    {
      name: "get_job_status",
      description: "Get the progress/result of a previously started bulk_toggle_code_quality job.",
      inputSchema: {
        type: "object",
        required: ["jobId"],
        properties: { jobId: { type: "string" } },
      },
      async handler({ input }) {
        const job = jobs.get(input.jobId);
        if (!job) throw new CanvasError("job_not_found", `No job with id ${input.jobId}`);
        return jobSnapshot(job);
      },
    },
  ],
  async open({ input }) {
    if (!serverInfo) serverInfo = await startServer();
    const params = new URLSearchParams();
    if (input?.enterprise) params.set("enterprise", input.enterprise);
    const qs = params.toString();
    const url = `http://127.0.0.1:${serverInfo.port}/${qs ? `?${qs}` : ""}`;
    const status = input?.enterprise ? `Enterprise: ${input.enterprise}` : "Ready";
    return { url, title: "Code Quality Enablement", status };
  },
});

await joinSession({ canvases: [canvas] });
