import { createPrivateKey, sign } from "node:crypto";

import { normalizeScope } from "./advisory.mjs";
import {
  sanitizeDiagnosticValue,
  selectDiagnosticHeaders,
} from "./diagnostics.mjs";

const API_BASE_URL = "https://api.github.com";
const API_VERSION = "2026-03-10";
const MAX_INSTALLATION_PAGES = 100;
const INSTALLATIONS_PER_PAGE = 100;

function httpError(message, status, details) {
  const error = new Error(message);
  error.status = status;
  error.details = details || null;
  return error;
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function createGitHubAppJwt(appIdentifier, privateKeyPem, now = Date.now()) {
  const issuer = String(appIdentifier || "").trim();
  if (!issuer || issuer.length > 100 || !/^[A-Za-z0-9_-]+$/.test(issuer)) {
    throw httpError("Enter a valid GitHub App ID or client ID.", 422);
  }

  const pem = String(privateKeyPem || "").trim();
  if (!pem || pem.length > 64 * 1024) {
    throw httpError("Select a valid GitHub App private key in PEM format.", 422);
  }

  let privateKey;
  try {
    privateKey = createPrivateKey(pem);
  } catch {
    throw httpError("The selected file is not a valid GitHub App private key.", 422);
  }
  if (privateKey.asymmetricKeyType !== "rsa") {
    throw httpError("GitHub App JWTs require an RSA private key.", 422);
  }

  const issuedAt = Math.floor(now / 1000) - 60;
  const header = base64UrlJson({ alg: "RS256", typ: "JWT" });
  const payload = base64UrlJson({
    iat: issuedAt,
    exp: issuedAt + 10 * 60,
    iss: issuer,
  });
  const unsignedToken = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(unsignedToken), privateKey).toString("base64url");
  return `${unsignedToken}.${signature}`;
}

export function requiredWritePermission(inputScope) {
  const scope = normalizeScope(inputScope);
  return scope.type === "enterprise"
    ? "enterprise_innersource_vulnerabilities"
    : "organization_innersource_vulnerabilities";
}

export function installationScope(installation) {
  const targetType = String(installation?.target_type || "").toLowerCase();
  const account = installation?.account || {};
  if (targetType === "enterprise" || (account.slug && !account.login)) {
    return { type: "enterprise", slug: String(account.slug || "").trim() };
  }
  if (targetType === "organization" || String(account.type || "").toLowerCase() === "organization") {
    return { type: "organization", slug: String(account.login || "").trim() };
  }
  return { type: "", slug: String(account.login || account.slug || "").trim() };
}

function sameScope(left, right) {
  return left.type === right.type && left.slug.toLowerCase() === right.slug.toLowerCase();
}

export function selectInstallation(installations, inputScope, explicitInstallationId) {
  const scope = normalizeScope(inputScope);
  const requestedId = String(explicitInstallationId || "").trim();
  const candidates = requestedId
    ? installations.filter((installation) => String(installation?.id) === requestedId)
    : installations.filter((installation) => sameScope(installationScope(installation), scope));

  if (!candidates.length) {
    const subject = requestedId ? `Installation ${requestedId}` : "This GitHub App";
    throw httpError(
      `${subject} is not installed on ${scope.type} "${scope.slug}".`,
      404,
    );
  }
  if (candidates.length > 1) {
    throw httpError(
      `Multiple installations matched ${scope.type} "${scope.slug}". Enter the installation ID explicitly.`,
      409,
    );
  }

  const installation = candidates[0];
  const actualScope = installationScope(installation);
  if (!sameScope(actualScope, scope)) {
    throw httpError(
      `Installation ${installation.id} belongs to ${actualScope.type || "another account"}/${actualScope.slug || "unknown"}, not ${scope.type}/${scope.slug}.`,
      422,
    );
  }
  if (installation.suspended_at) {
    throw httpError(`Installation ${installation.id} is suspended.`, 403);
  }

  const permission = requiredWritePermission(scope);
  const access = String(installation.permissions?.[permission] || "").toLowerCase();
  if (access !== "write") {
    throw httpError(
      `The installation lacks ${permission}:write. Set the GitHub App permission to "Read and write", then approve the permission change for this installation.`,
      403,
      { permission, access: access || "none" },
    );
  }
  return installation;
}

async function appRequest(
  path,
  jwt,
  { method = "GET", fetchImpl = globalThis.fetch, logger } = {},
) {
  const startedAt = Date.now();
  let response;
  try {
    response = await fetchImpl(`${API_BASE_URL}${path}`, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${jwt}`,
        "User-Agent": "ghas-copilot-canvas",
        "X-GitHub-Api-Version": API_VERSION,
      },
    });
  } catch (error) {
    if (typeof logger === "function") {
      logger({
        level: "error",
        source: "github-app",
        operation: `${method} ${path}`,
        durationMs: Date.now() - startedAt,
        request: {
          method,
          path,
          authentication: "GitHub App JWT (redacted)",
        },
        error: { message: error.message },
      });
    }
    throw httpError(`GitHub App request failed: ${error.message}`, 502);
  }

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      if (typeof logger === "function") {
        logger({
          level: "error",
          source: "github-app",
          operation: `${method} ${path}`,
          durationMs: Date.now() - startedAt,
          request: {
            method,
            path,
            authentication: "GitHub App JWT (redacted)",
          },
          response: {
            status: response.status,
            headers: selectDiagnosticHeaders(response.headers),
            body: text,
          },
        });
      }
      throw httpError("GitHub returned an invalid response while authenticating the App.", 502);
    }
  }
  if (typeof logger === "function") {
    logger({
      level: response.ok ? "info" : "error",
      source: "github-app",
      operation: `${method} ${path}`,
      durationMs: Date.now() - startedAt,
      request: {
        method,
        path,
        authentication: "GitHub App JWT (redacted)",
        headers: {
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": API_VERSION,
        },
      },
      response: {
        status: response.status,
        headers: selectDiagnosticHeaders(response.headers),
        body: sanitizeDiagnosticValue(data),
      },
    });
  }
  if (!response.ok) {
    throw httpError(
      data?.message || `GitHub App request failed with HTTP ${response.status}.`,
      response.status,
      data?.errors || data?.documentation_url,
    );
  }
  return data;
}

async function listInstallations(jwt, fetchImpl, logger) {
  const installations = [];
  for (let page = 1; page <= MAX_INSTALLATION_PAGES; page += 1) {
    const result = await appRequest(
      `/app/installations?per_page=${INSTALLATIONS_PER_PAGE}&page=${page}`,
      jwt,
      { fetchImpl, logger },
    );
    if (!Array.isArray(result)) {
      throw httpError("GitHub returned an invalid installation list.", 502);
    }
    installations.push(...result);
    if (result.length < INSTALLATIONS_PER_PAGE) return installations;
  }
  throw httpError("The App has more than 10,000 installations. Enter the installation ID explicitly.", 422);
}

function normalizeInstallationId(value) {
  const id = String(value || "").trim();
  if (!id) return "";
  if (!/^[1-9]\d*$/.test(id)) {
    throw httpError("Installation ID must be a positive integer.", 422);
  }
  return id;
}

export async function generateInstallationAccessToken(inputScope, options = {}) {
  const scope = normalizeScope(inputScope);
  const installationId = normalizeInstallationId(options.installationId);
  const jwt = createGitHubAppJwt(options.appIdentifier, options.privateKey, options.now);
  const fetchImpl = options.fetchImpl || globalThis.fetch;

  const installations = installationId
    ? [await appRequest(`/app/installations/${installationId}`, jwt, { fetchImpl, logger: options.logger })]
    : await listInstallations(jwt, fetchImpl, options.logger);
  const installation = selectInstallation(installations, scope, installationId);
  const result = await appRequest(
    `/app/installations/${encodeURIComponent(installation.id)}/access_tokens`,
    jwt,
    { method: "POST", fetchImpl, logger: options.logger },
  );

  if (!result?.token || !result?.expires_at) {
    throw httpError("GitHub did not return an installation access token and expiry.", 502);
  }

  const permission = requiredWritePermission(scope);
  return {
    token: result.token,
    expiresAt: result.expires_at,
    installationId: String(installation.id),
    appSlug: installation.app_slug || null,
    scope,
    permissions: result.permissions || installation.permissions || {},
    permission: {
      name: permission,
      access: String(installation.permissions?.[permission] || "").toLowerCase(),
    },
  };
}
