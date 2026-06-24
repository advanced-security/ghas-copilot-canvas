// Thin wrapper around the authenticated `gh` CLI. The extension shells out to
// `gh api` for every GitHub call so it inherits the user's existing auth.
//
// Auth note: a `GH_TOKEN`/`GITHUB_TOKEN` env var (if present) takes precedence
// over gh's stored keyring token, and may carry fewer scopes than the custom
// patterns API requires (read:org/admin:org, admin:enterprise). When a call
// fails with 401/403, we transparently retry once with those env tokens
// stripped so gh falls back to the keyring login.

import { spawn } from "node:child_process";

const GH = process.platform === "win32" ? "gh.exe" : "gh";

function run(args, { input, stripTokens = false } = {}) {
    return new Promise((resolve) => {
        const env = { ...process.env, GH_PROMPT_DISABLED: "1", CLICOLOR: "0" };
        if (stripTokens) {
            delete env.GH_TOKEN;
            delete env.GITHUB_TOKEN;
        }
        let child;
        try {
            child = spawn(GH, args, { windowsHide: true, env });
        } catch (err) {
            resolve({ code: -1, stdout: "", stderr: String(err && err.message ? err.message : err) });
            return;
        }
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d) => (stdout += d.toString()));
        child.stderr.on("data", (d) => (stderr += d.toString()));
        child.on("error", (err) => resolve({ code: -1, stdout, stderr: stderr + String(err.message) }));
        child.on("close", (code) => resolve({ code, stdout, stderr }));
        if (input != null) child.stdin.write(input);
        child.stdin.end();
    });
}

function looksLikeAuthScopeIssue({ code, stdout, stderr }) {
    if (code === 0) return false;
    const blob = `${stdout}\n${stderr}`.toLowerCase();
    return /http 401|http 403|requires? .*scope|needs the .* scope|must have admin|bad credentials|requires authentication/.test(blob);
}

// Run, retrying once with env tokens stripped if the first attempt hits an
// auth/scope wall.
async function runWithFallback(args, opts = {}) {
    const first = await run(args, opts);
    if (looksLikeAuthScopeIssue(first)) {
        return run(args, { ...opts, stripTokens: true });
    }
    return first;
}

function parseInclude(raw) {
    const text = (raw || "").replace(/\r\n/g, "\n");
    const blankIdx = text.indexOf("\n\n");
    let status = 0;
    const firstLine = text.split("\n", 1)[0] || "";
    const m = firstLine.match(/HTTP\/[\d.]+\s+(\d+)/i);
    if (m) status = Number(m[1]);
    const body = blankIdx >= 0 ? text.slice(blankIdx + 2) : text;
    return { status, body: body.trim() };
}

function tryJson(s) {
    if (!s) return undefined;
    try {
        return JSON.parse(s);
    } catch {
        return undefined;
    }
}

// GET a paginated JSON array (orgs, repos). gh merges pages into one array.
export async function ghList(path) {
    const { code, stdout, stderr } = await runWithFallback(["api", "--paginate", path]);
    if (code !== 0) {
        const data = tryJson(stdout);
        return {
            ok: false,
            status: data?.status ? Number(data.status) : 0,
            error: data?.message || stderr.trim() || "gh request failed",
            data: [],
        };
    }
    return { ok: true, status: 200, data: tryJson(stdout) ?? [] };
}

// Generic call with explicit status via --include. method defaults to GET.
export async function ghApi(path, { method = "GET", body } = {}) {
    const args = ["api", "--include", "-X", method, path];
    if (body !== undefined) args.push("--input", "-");
    const opts = { input: body !== undefined ? JSON.stringify(body) : undefined };
    const { code, stdout, stderr } = await runWithFallback(args, opts);
    const { status, body: raw } = parseInclude(stdout);
    const data = tryJson(raw);
    const ok = status >= 200 && status < 300;
    return {
        ok,
        status: status || (code === 0 ? 200 : 0),
        data,
        raw,
        error: ok ? undefined : data?.message || stderr.trim() || raw || "gh request failed",
    };
}

// Fetch a raw file from a repo via the contents API.
export async function ghRawFile(owner, repo, path, ref) {
    const args = ["api", "-H", "Accept: application/vnd.github.raw+json", `/repos/${owner}/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`];
    const { code, stdout, stderr } = await runWithFallback(args);
    if (code !== 0) {
        const data = tryJson(stdout);
        return { ok: false, error: data?.message || stderr.trim() || "failed to fetch file" };
    }
    return { ok: true, content: stdout };
}
