import { spawn } from "node:child_process";
import {
  graphqlNodesToAdvisories,
  normalizeScope,
  validateOsv,
} from "./advisory.mjs";
import { selectDiagnosticHeaders } from "./diagnostics.mjs";

const GH = process.platform === "win32" ? "gh.exe" : "gh";
const API_VERSION = "2026-03-10";
const FEATURE_HEADER = "GraphQL-Features: innersource_alerting";
const MAX_GRAPHQL_PAGES = 100;

function run(args, { input, token, stripDefaultTokens = false } = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env, GH_PROMPT_DISABLED: "1", CLICOLOR: "0", NO_COLOR: "1" };
    if (stripDefaultTokens) {
      delete env.GH_TOKEN;
      delete env.GITHUB_TOKEN;
    }
    if (token) env.GH_TOKEN = token;

    let child;
    try {
      child = spawn(GH, args, { env, windowsHide: true });
    } catch (error) {
      resolve({ code: -1, stdout: "", stderr: error.message });
      return;
    }

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("error", (error) => resolve({ code: -1, stdout, stderr: `${stderr}${error.message}` }));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (input != null) child.stdin.write(input);
    child.stdin.end();
  });
}

function parseJson(text) {
  const value = String(text || "").trim();
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function parseIncludedResponse(text) {
  const value = String(text || "").replace(/\r\n/g, "\n");
  if (!value.startsWith("HTTP/")) {
    return { status: null, headers: {}, bodyText: value };
  }
  const headerEnd = value.indexOf("\n\n");
  if (headerEnd < 0) return { status: null, headers: {}, bodyText: value };
  const headerLines = value.slice(0, headerEnd).split("\n");
  const statusMatch = headerLines.shift()?.match(/^HTTP\/\S+\s+(\d{3})/i);
  const headers = {};
  for (const line of headerLines) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    headers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
  }
  return {
    status: statusMatch ? Number(statusMatch[1]) : null,
    headers,
    bodyText: value.slice(headerEnd + 2),
  };
}

function normalizeApiResult(result) {
  const included = parseIncludedResponse(result.stdout);
  return {
    ...result,
    stdout: included.bodyText,
    httpStatus: included.status,
    responseHeaders: included.headers,
  };
}

function emitDiagnostic(logger, entry) {
  if (typeof logger === "function") logger(entry);
}

function authFailure(result) {
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return result.code !== 0
    && /http 401|http 403|bad credentials|requires authentication|resource not accessible|insufficient_scopes|insufficient scopes|required scopes|not been granted/.test(text);
}

async function runWithAuthFallback(args, options = {}, onRetry) {
  const first = await run(args, options);
  if (!options.token && authFailure(first)) {
    if (onRetry) onRetry(normalizeApiResult(first));
    const result = await run(args, { ...options, stripDefaultTokens: true });
    return { ...result, authSource: "gh credential store" };
  }
  return { ...first, authSource: options.token ? "installation token" : "gh default credential" };
}

function commandError(result, fallback) {
  const data = parseJson(result.stdout);
  const statusMatch = `${result.stdout}\n${result.stderr}`.match(/HTTP\s+(\d{3})/i);
  const error = new Error(data?.message || result.stderr.trim() || result.stdout.trim() || fallback);
  error.status = result.httpStatus || (statusMatch ? Number(statusMatch[1]) : 502);
  error.details = data?.errors || data?.documentation_url || null;
  return error;
}

async function graphql(query, variables, options = {}) {
  const startedAt = Date.now();
  const logger = options.logger;
  const input = JSON.stringify({ query, variables });
  const args = ["api", "--include", "graphql", "-H", FEATURE_HEADER, "--input", "-"];
  const request = {
    method: "POST",
    path: "/graphql",
    authentication: "gh CLI user credential",
    headers: { "GraphQL-Features": "innersource_alerting" },
    body: { query, variables },
  };
  const logRetry = (attempt) => emitDiagnostic(logger, {
    level: "warning",
    source: "github-graphql",
    operation: "POST /graphql",
    durationMs: Date.now() - startedAt,
    message: "The default gh credential was rejected; retrying with the credential stored by gh auth login.",
    request,
    response: {
      status: attempt.httpStatus,
      headers: selectDiagnosticHeaders(attempt.responseHeaders),
      body: parseJson(attempt.stdout) ?? attempt.stdout,
    },
  });
  let result = normalizeApiResult(await runWithAuthFallback(args, { input }, logRetry));
  let data = parseJson(result.stdout);

  if (result.code === 0 && data?.errors && !data?.data) {
    const errorText = JSON.stringify(data.errors).toLowerCase();
    if (/forbidden|unauthorized|resource not accessible|insufficient_scopes|insufficient scopes|required scopes|not been granted/.test(errorText)) {
      logRetry(result);
      result = normalizeApiResult(await run(args, { input, stripDefaultTokens: true }));
      result.authSource = "gh credential store";
      data = parseJson(result.stdout);
    }
  }

  emitDiagnostic(logger, {
    level: result.code === 0 && !data?.errors?.length ? "info" : "error",
    source: "github-graphql",
    operation: "POST /graphql",
    durationMs: Date.now() - startedAt,
    message: `Authentication: ${result.authSource || "gh CLI user credential"}.`,
    request,
    response: {
      status: result.httpStatus,
      headers: selectDiagnosticHeaders(result.responseHeaders),
      body: data ?? result.stdout,
    },
  });
  if (result.code !== 0) throw commandError(result, "GraphQL request failed.");
  if (!data) throw new Error("GitHub returned an invalid GraphQL response.");
  if (data.errors?.length) {
    const error = new Error(data.errors.map((item) => item.message).join("; "));
    error.status = 400;
    error.details = data.errors;
    throw error;
  }
  return data.data;
}

function innersourceQuery(scopeType) {
  const ownerField = scopeType === "enterprise" ? "enterprise(slug: $slug)" : "organization(login: $slug)";
  const ownerIdentity = scopeType === "enterprise" ? "scopeIdentity: slug" : "scopeIdentity: login";
  return `
    query($slug: String!, $cursor: String) {
      owner: ${ownerField} {
        ${ownerIdentity}
        innersourceVulnerabilities(first: 100, after: $cursor) {
          nodes {
            severity
            vulnerableVersionRange
            firstPatchedVersion { identifier }
            updatedAt
            package { ecosystem name }
            advisory {
              ghsaId
              summary
              description
              severity
              permalink
              publishedAt
              updatedAt
              withdrawnAt
              identifiers { type value }
              references { url }
              cvssSeverities {
                cvssV3 { vectorString score }
                cvssV4 { vectorString score }
              }
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  `;
}

export async function listInnersourceAdvisories(inputScope, options = {}) {
  const scope = normalizeScope(inputScope);
  const nodes = [];
  let cursor = null;
  let page = 0;
  let hasNextPage = false;

  while (page < MAX_GRAPHQL_PAGES) {
    const data = await graphql(
      innersourceQuery(scope.type),
      { slug: scope.slug, cursor },
      { logger: options.logger },
    );
    if (!data?.owner) {
      const error = new Error(`${scope.type === "enterprise" ? "Enterprise" : "Organization"} "${scope.slug}" was not found or is not visible.`);
      error.status = 404;
      throw error;
    }
    const connection = data.owner.innersourceVulnerabilities;
    nodes.push(...(connection?.nodes || []));
    page += 1;
    hasNextPage = Boolean(connection?.pageInfo?.hasNextPage);
    if (!hasNextPage) break;
    cursor = connection.pageInfo.endCursor;
  }

  if (hasNextPage) {
    const error = new Error(`Stopped after ${MAX_GRAPHQL_PAGES * 100} vulnerability ranges. Narrow the source scope.`);
    error.status = 422;
    throw error;
  }
  return graphqlNodesToAdvisories(nodes, scope);
}

async function api(
  path,
  {
    method = "GET",
    body,
    token,
    logger,
    includeMetadata = false,
    stripDefaultTokens = false,
  } = {},
) {
  const startedAt = Date.now();
  const args = [
    "api",
    "--include",
    "-X",
    method,
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    `X-GitHub-Api-Version: ${API_VERSION}`,
    path,
  ];
  if (body !== undefined) args.push("--input", "-");
  const result = normalizeApiResult(await run(args, {
    input: body === undefined ? undefined : JSON.stringify(body),
    token,
    stripDefaultTokens,
  }));
  const data = parseJson(result.stdout);
  emitDiagnostic(logger, {
    level: result.code === 0 ? "info" : "error",
    source: "github-rest",
    operation: `${method} ${path}`,
    durationMs: Date.now() - startedAt,
    request: {
      method,
      path,
      authentication: token
        ? "GitHub App installation token (redacted)"
        : stripDefaultTokens
          ? "gh auth login credential"
          : "gh default credential",
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
      },
      ...(body === undefined ? {} : { body }),
    },
    response: {
      status: result.httpStatus,
      headers: selectDiagnosticHeaders(result.responseHeaders),
      body: data ?? result.stdout,
    },
  });
  if (result.code !== 0) throw commandError(result, "GitHub API request failed.");
  const responseData = data ?? {};
  return includeMetadata
    ? {
        data: responseData,
        status: result.httpStatus,
        headers: result.responseHeaders,
      }
    : responseData;
}

export function configuredDeployToken() {
  return Boolean(process.env.GH_INNERSOURCE_TOKEN);
}

function deploymentToken(explicitToken) {
  const token = String(explicitToken || process.env.GH_INNERSOURCE_TOKEN || "").trim();
  if (!token) {
    const error = new Error("A GitHub App installation token is required. Paste one for this request or set GH_INNERSOURCE_TOKEN before starting Copilot.");
    error.status = 401;
    throw error;
  }
  return token;
}

function syncPath(scope) {
  const encoded = encodeURIComponent(scope.slug);
  return scope.type === "enterprise"
    ? `/enterprises/${encoded}/innersource-vulnerabilities/sync`
    : `/organizations/${encoded}/innersource-vulnerabilities/sync`;
}

export async function startAdvisorySync(inputScope, advisory, explicitToken, options = {}) {
  const scope = normalizeScope(inputScope);
  const validation = validateOsv(advisory);
  if (!validation.valid) {
    const error = new Error(validation.errors.join(" "));
    error.status = 422;
    error.details = validation;
    throw error;
  }
  const token = deploymentToken(explicitToken);
  const result = await api(syncPath(scope), {
    method: "POST",
    body: { vulnerabilities: [advisory] },
    token,
    logger: options.logger,
  });
  if (!result.id) {
    const error = new Error("GitHub accepted the request but did not return a sync job ID.");
    error.status = 502;
    throw error;
  }
  return { ...result, scope };
}

export async function getAdvisorySyncStatus(inputScope, jobId, explicitToken, options = {}) {
  const scope = normalizeScope(inputScope);
  const id = String(jobId || "").trim();
  if (!id) throw new Error("Sync job ID is required.");
  const token = deploymentToken(explicitToken);
  return api(`${syncPath(scope)}/status/${encodeURIComponent(id)}`, {
    token,
    logger: options.logger,
  });
}

export async function waitForAdvisorySync(inputScope, jobId, options = {}) {
  const timeoutMs = options.timeoutMs || 60_000;
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const result = await getAdvisorySyncStatus(inputScope, jobId, options.token, {
      logger: options.logger,
    });
    if (!["queued", "processing"].includes(result.status)) return result;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return { status: "processing", id: jobId, timedOut: true };
}

export function parseOauthScopes(value) {
  return [...new Set(
    String(value || "")
      .split(",")
      .map((scope) => scope.trim())
      .filter(Boolean),
  )].sort();
}

async function userCredential(label, stripDefaultTokens) {
  const response = await api("/user", {
    includeMetadata: true,
    stripDefaultTokens,
  });
  return {
    label,
    login: response.data.login || null,
    name: response.data.name || null,
    scopes: parseOauthScopes(response.headers["x-oauth-scopes"]),
  };
}

export async function currentUser() {
  const credentials = [];
  const errors = [];
  for (const [label, stripDefaultTokens] of [
    ["Default gh credential", false],
    ["Credential stored by gh auth login", true],
  ]) {
    try {
      const credential = await userCredential(label, stripDefaultTokens);
      const duplicate = credentials.some((existing) =>
        existing.login === credential.login
        && existing.scopes.join(",") === credential.scopes.join(",")
      );
      if (!duplicate) credentials.push(credential);
    } catch (error) {
      errors.push(`${label}: ${error.message}`);
    }
  }
  const primary = credentials[0];
  return {
    login: primary?.login || null,
    name: primary?.name || null,
    credentials,
    ...(credentials.length ? {} : { error: errors.join("; ") || "gh is not authenticated" }),
  };
}

export { API_VERSION };
