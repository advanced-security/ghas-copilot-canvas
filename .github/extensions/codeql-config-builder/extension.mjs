import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, normalize } from "node:path";
import { CanvasError, createCanvas, joinSession } from "@github/copilot-sdk/extension";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = resolve(__dirname, "public");

// --- gh helpers -------------------------------------------------------------

async function gh(args, { input } = {}) {
  try {
    const { stdout } = await execFileAsync("gh", args, {
      maxBuffer: 16 * 1024 * 1024,
      input,
    });
    return stdout;
  } catch (err) {
    const stderr = (err.stderr || "").toString().trim();
    const stdout = (err.stdout || "").toString().trim();
    const msg = stderr || stdout || err.message || "gh command failed";
    const e = new Error(msg);
    e.code = "gh_error";
    throw e;
  }
}

async function ghJson(args, opts) {
  const out = await gh(args, opts);
  if (!out.trim()) return null;
  try { return JSON.parse(out); } catch { return out; }
}

async function ghApi(path, { method = "GET", rawBody } = {}) {
  const args = ["api", "-X", method, path, "-H", "Accept: application/vnd.github+json"];
  if (rawBody !== undefined) {
    args.push("--input", "-");
    return ghJson(args, { input: rawBody });
  }
  return ghJson(args);
}

// --- CodeQL config writer ---------------------------------------------------

async function writeCodeqlConfig({ owner, repo, branch, path, yamlContent, message }) {
  if (!owner || !repo) throw new CanvasError("missing_repo", "owner and repo are required");
  if (!yamlContent) throw new CanvasError("missing_content", "yamlContent is required");
  const filePath = path || ".github/codeql/codeql-config.yml";
  const commitMessage = message || "chore: add CodeQL configuration";

  let sha;
  try {
    const args = ["api", `/repos/${owner}/${repo}/contents/${filePath}`];
    if (branch) args.push("-f", `ref=${branch}`);
    const existing = await ghJson(args);
    sha = existing?.sha;
  } catch {
    sha = undefined;
  }

  const body = {
    message: commitMessage,
    content: Buffer.from(yamlContent, "utf8").toString("base64"),
  };
  if (branch) body.branch = branch;
  if (sha) body.sha = sha;

  const res = await ghApi(`/repos/${owner}/${repo}/contents/${filePath}`, {
    method: "PUT",
    rawBody: JSON.stringify(body),
  });
  return {
    ok: true,
    path: filePath,
    branch: res?.content?.branch || branch,
    html_url: res?.content?.html_url,
    commit_sha: res?.commit?.sha,
  };
}

async function readCodeqlConfig({ owner, repo, branch, path }) {
  if (!owner || !repo) throw new CanvasError("missing_repo", "owner and repo are required");
  const filePath = path || ".github/codeql/codeql-config.yml";
  const args = ["api", `/repos/${owner}/${repo}/contents/${filePath}`];
  if (branch) args.push("-f", `ref=${branch}`);
  const data = await ghJson(args);
  if (!data?.content) return { exists: false, path: filePath };
  const yamlContent = Buffer.from(data.content, "base64").toString("utf8");
  return { exists: true, path: filePath, sha: data.sha, html_url: data.html_url, yamlContent };
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
        if (req.method === "GET" && p === "/api/load-config") {
          return sendJson(res, 200, await readCodeqlConfig({
            owner: url.searchParams.get("owner"),
            repo: url.searchParams.get("repo"),
            branch: url.searchParams.get("branch") || undefined,
            path: url.searchParams.get("path") || undefined,
          }));
        }
        if (req.method === "POST" && p === "/api/commit-config") {
          return sendJson(res, 200, await writeCodeqlConfig(await readJsonBody(req)));
        }
        return sendJson(res, 404, { error: "Not found" });
      }

      if (req.method === "GET") return serveStatic(req, res, p);
      res.writeHead(405).end();
    } catch (err) {
      const code = err.code === "gh_error" ? 502 : err.code ? 400 : 500;
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
  id: "codeql-config-builder",
  displayName: "CodeQL Config Builder",
  description:
    "Form-driven builder for CodeQL configuration YAML (see gh.io/codeql-config). Supports name, disable-default-queries, threat-models, queries, packs, paths, paths-ignore, query-filters; can preview, download, or commit the file to a repo (default path .github/codeql/codeql-config.yml).",
  inputSchema: {
    type: "object",
    properties: {
      owner: { type: "string", description: "Optional repo owner to pre-fill the commit target" },
      repo: { type: "string", description: "Optional repo name to pre-fill the commit target" },
      branch: { type: "string" },
      path: { type: "string", description: "Config file path (default .github/codeql/codeql-config.yml)" },
    },
    additionalProperties: false,
  },
  actions: [
    {
      name: "load_config",
      description: "Load an existing CodeQL config YAML from a repo (if present).",
      inputSchema: {
        type: "object",
        required: ["owner", "repo"],
        properties: {
          owner: { type: "string" },
          repo: { type: "string" },
          branch: { type: "string" },
          path: { type: "string" },
        },
      },
      async handler({ input }) { return readCodeqlConfig(input); },
    },
    {
      name: "write_codeql_config",
      description:
        "Commit a CodeQL configuration YAML to a repo (default path .github/codeql/codeql-config.yml).",
      inputSchema: {
        type: "object",
        required: ["owner", "repo", "yamlContent"],
        properties: {
          owner: { type: "string" },
          repo: { type: "string" },
          branch: { type: "string" },
          path: { type: "string" },
          yamlContent: { type: "string" },
          message: { type: "string" },
        },
      },
      async handler({ input }) { return writeCodeqlConfig(input); },
    },
  ],
  async open({ input }) {
    if (!serverInfo) serverInfo = await startServer();
    const params = new URLSearchParams();
    for (const k of ["owner", "repo", "branch", "path"]) {
      if (input?.[k]) params.set(k, input[k]);
    }
    const qs = params.toString();
    const url = `http://127.0.0.1:${serverInfo.port}/${qs ? `?${qs}` : ""}`;
    const status = input?.owner && input?.repo ? `${input.owner}/${input.repo}` : "Ready";
    return { url, title: "CodeQL Config Builder", status };
  },
});

await joinSession({ canvases: [canvas] });
