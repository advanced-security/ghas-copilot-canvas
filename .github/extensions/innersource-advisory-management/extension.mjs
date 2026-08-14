import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, extname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { createCanvas, joinSession } from "@github/copilot-sdk/extension";

import { generateInstallationAccessToken } from "./app-auth.mjs";
import { validateOsv } from "./advisory.mjs";
import { createDiagnosticLog } from "./diagnostics.mjs";
import {
  API_VERSION,
  configuredDeployToken,
  currentUser,
  getAdvisorySyncStatus,
  listInnersourceAdvisories,
  startAdvisorySync,
  waitForAdvisorySync,
} from "./github.mjs";

const extensionDir = dirname(fileURLToPath(import.meta.url));
const publicDir = resolve(extensionDir, "public");
const sharedModule = resolve(extensionDir, "advisory.mjs");
const servers = new Map();
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
};

function sendJson(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(body);
}

function createCredentialVault() {
  let credential = null;

  function current() {
    if (!credential) return null;
    const expiresAt = Date.parse(credential.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now() + 30_000) {
      credential = null;
    }
    return credential;
  }

  return {
    set(value) {
      credential = value;
    },
    clear() {
      credential = null;
    },
    metadata() {
      const value = current();
      if (!value) return null;
      return {
        appSlug: value.appSlug,
        expiresAt: value.expiresAt,
        installationId: value.installationId,
        permission: value.permission,
        permissions: value.permissions,
        scope: value.scope,
      };
    },
    tokenFor(scope) {
      const value = current();
      if (!value) return null;
      const sameType = value.scope.type === scope?.type;
      const sameSlug = value.scope.slug.toLowerCase() === String(scope?.slug || "").trim().toLowerCase();
      return sameType && sameSlug ? value.token : null;
    },
  };
}

async function readJsonBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) {
      const error = new Error("Request body exceeds 2 MB.");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Request body must be valid JSON.");
    error.status = 400;
    throw error;
  }
}

async function serveFile(response, filePath) {
  try {
    const data = await readFile(filePath);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Length": data.length,
      "Content-Type": MIME_TYPES[extname(filePath)] || "application/octet-stream",
    });
    response.end(data);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

async function serveStatic(response, pathname) {
  if (pathname === "/advisory.js") return serveFile(response, sharedModule);
  const staticRelative = normalize(pathname === "/" ? "index.html" : pathname).replace(/^([\\/])+/, "");
  const fullPath = resolve(join(publicDir, staticRelative));
  const pathFromPublic = relative(publicDir, fullPath);
  if (pathFromPublic.startsWith("..") || isAbsolute(pathFromPublic)) {
    response.writeHead(403).end();
    return;
  }
  return serveFile(response, fullPath);
}

async function handleApi(request, response, url, credentialVault, diagnosticLog) {
  if (request.method === "GET" && url.pathname === "/api/logs") {
    return sendJson(response, 200, diagnosticLog.snapshot(url.searchParams.get("after")));
  }

  if (request.method === "DELETE" && url.pathname === "/api/logs") {
    return sendJson(response, 200, diagnosticLog.clear());
  }

  if (request.method === "GET" && url.pathname === "/api/context") {
    return sendJson(response, 200, {
      ...(await currentUser()),
      apiVersion: API_VERSION,
      deployTokenConfigured: configuredDeployToken(),
      generatedDeployToken: credentialVault.metadata(),
    });
  }

  if (request.method === "POST" && url.pathname === "/api/list-advisories") {
    const body = await readJsonBody(request);
    const advisories = await listInnersourceAdvisories(body.scope, {
      logger: diagnosticLog.add,
    });
    return sendJson(response, 200, { ok: true, scope: body.scope, advisories });
  }

  if (request.method === "POST" && url.pathname === "/api/validate") {
    const body = await readJsonBody(request);
    const validation = validateOsv(body.advisory);
    diagnosticLog.add({
      level: validation.valid ? "info" : "warning",
      source: "canvas",
      operation: "Validate OSV payload",
      request: { body: body.advisory },
      response: { status: validation.valid ? 200 : 422, body: validation },
    });
    return sendJson(response, validation.valid ? 200 : 422, validation);
  }

  if (request.method === "POST" && url.pathname === "/api/installation-token") {
    const body = await readJsonBody(request);
    const credential = await generateInstallationAccessToken(body.scope, {
      appIdentifier: body.appIdentifier,
      installationId: body.installationId,
      privateKey: body.privateKey,
      logger: diagnosticLog.add,
    });
    credentialVault.set(credential);
    return sendJson(response, 201, {
      ok: true,
      credential: credentialVault.metadata(),
    });
  }

  if (request.method === "DELETE" && url.pathname === "/api/installation-token") {
    credentialVault.clear();
    return sendJson(response, 200, { ok: true });
  }

  if (request.method === "POST" && url.pathname === "/api/deploy") {
    const body = await readJsonBody(request);
    const token = body.token || credentialVault.tokenFor(body.scope);
    const job = await startAdvisorySync(body.scope, body.advisory, token, {
      logger: diagnosticLog.add,
    });
    return sendJson(response, 202, { ok: true, job });
  }

  if (request.method === "POST" && url.pathname === "/api/sync-status") {
    const body = await readJsonBody(request);
    const token = body.token || credentialVault.tokenFor(body.scope);
    const result = await getAdvisorySyncStatus(body.scope, body.jobId, token, {
      logger: diagnosticLog.add,
    });
    const pending = ["queued", "processing"].includes(result.status);
    return sendJson(response, pending ? 202 : 200, { ok: true, pending, result });
  }

  return sendJson(response, 404, { error: "Not found" });
}

function errorResponse(response, error) {
  const status = Number(error.status) || 500;
  sendJson(response, status, {
    error: error.message || "Unexpected error",
    details: error.details || null,
  });
}

async function startServer(instanceId) {
  const credentialVault = createCredentialVault();
  const diagnosticLog = createDiagnosticLog();
  diagnosticLog.add({
    source: "canvas",
    operation: "Diagnostic log initialized",
    message: "Activity is held in memory, bounded to 100 entries, and cleared when this canvas closes.",
  });
  let expectedOrigin = "";
  const server = createServer(async (request, response) => {
    let url;
    try {
      url = new URL(request.url, "http://127.0.0.1");
      if (url.pathname.startsWith("/api/")) {
        const origin = String(request.headers.origin || "");
        if (origin && origin !== expectedOrigin) {
          const error = new Error("Cross-origin API requests are not allowed.");
          error.status = 403;
          throw error;
        }
        return await handleApi(request, response, url, credentialVault, diagnosticLog);
      }
      if (request.method !== "GET") {
        response.writeHead(405).end();
        return;
      }
      return await serveStatic(response, url.pathname);
    } catch (error) {
      if (url?.pathname !== "/api/logs") {
        diagnosticLog.add({
          level: "error",
          source: "canvas-api",
          operation: `${request.method || "REQUEST"} ${url?.pathname || request.url || "/"}`,
          error: {
            status: Number(error.status) || 500,
            message: error.message || "Unexpected error",
            details: error.details || null,
          },
        });
      }
      errorResponse(response, error);
    }
  });

  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  expectedOrigin = `http://127.0.0.1:${port}`;
  return { credentialVault, diagnosticLog, instanceId, server, url: `${expectedOrigin}/` };
}

const scopeProperties = {
  sourceType: { type: "string", enum: ["enterprise", "organization"] },
  sourceSlug: { type: "string" },
  targetType: { type: "string", enum: ["enterprise", "organization"] },
  targetSlug: { type: "string" },
  previewFeatures: { type: "boolean" },
  advisoryId: { type: "string" },
};

const canvas = createCanvas({
  id: "innersource-advisory-management",
  displayName: "Innersource Advisory Management",
  description: "Load GA GHIS advisories from an organization or enterprise, edit OSV data with a CVSS calculator, and deploy to an enterprise or an explicitly enabled private preview organization target.",
  inputSchema: {
    type: "object",
    properties: scopeProperties,
    additionalProperties: false,
  },
  actions: [
    {
      name: "list_advisories",
      description: "List innersource advisories from an enterprise or organization GraphQL scope.",
      inputSchema: {
        type: "object",
        required: ["scopeType", "slug"],
        properties: {
          scopeType: { type: "string", enum: ["enterprise", "organization"] },
          slug: { type: "string" },
          query: { type: "string", description: "Optional ID, summary, ecosystem, or package filter." },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        additionalProperties: false,
      },
      async handler({ input }) {
        const advisories = await listInnersourceAdvisories({ type: input.scopeType, slug: input.slug });
        const query = String(input.query || "").trim().toLowerCase();
        const filtered = query
          ? advisories.filter((item) => JSON.stringify(item).toLowerCase().includes(query))
          : advisories;
        return {
          scope: { type: input.scopeType, slug: input.slug },
          total: advisories.length,
          returned: Math.min(filtered.length, input.limit || 50),
          advisories: filtered.slice(0, input.limit || 50),
        };
      },
    },
    {
      name: "validate_advisory",
      description: "Validate a single OSV advisory against GitHub innersource advisory requirements.",
      inputSchema: {
        type: "object",
        required: ["advisory"],
        properties: { advisory: { type: "object" } },
        additionalProperties: false,
      },
      async handler({ input }) {
        return validateOsv(input.advisory);
      },
    },
    {
      name: "sync_advisory",
      description: "Create, update, or withdraw one innersource advisory. Requires GH_INNERSOURCE_TOKEN to contain a GitHub App installation token.",
      inputSchema: {
        type: "object",
        required: ["scopeType", "slug", "advisory"],
        properties: {
          scopeType: { type: "string", enum: ["enterprise", "organization"] },
          slug: { type: "string" },
          advisory: { type: "object" },
        },
        additionalProperties: false,
      },
      async handler({ input }) {
        const scope = { type: input.scopeType, slug: input.slug };
        const job = await startAdvisorySync(scope, input.advisory);
        return { job, result: await waitForAdvisorySync(scope, job.id) };
      },
    },
  ],
  async open({ instanceId, input }) {
    let entry = servers.get(instanceId);
    if (!entry) {
      entry = await startServer(instanceId);
      servers.set(instanceId, entry);
    }
    const params = new URLSearchParams();
    for (const key of Object.keys(scopeProperties)) {
      if (input?.[key]) params.set(key, input[key]);
    }
    const query = params.toString();
    return {
      title: "Innersource Advisory Management",
      status: input?.sourceSlug ? `Source: ${input.sourceSlug}` : "Ready",
      url: `${entry.url}${query ? `?${query}` : ""}`,
    };
  },
  async onClose({ instanceId }) {
    const entry = servers.get(instanceId);
    if (!entry) return;
    servers.delete(instanceId);
    entry.credentialVault.clear();
    await new Promise((resolveClose) => entry.server.close(resolveClose));
  },
});

const session = await joinSession({ canvases: [canvas] });
await session.log("Innersource Advisory Management canvas ready", { ephemeral: true });
