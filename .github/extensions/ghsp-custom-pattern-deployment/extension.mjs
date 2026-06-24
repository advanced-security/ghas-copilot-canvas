// Extension: ss-custom-patterns
// Deploy secret scanning custom patterns from patterns.yml files at the
// enterprise / org / repo level via the private-preview REST API.

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { joinSession, createCanvas } from "@github/copilot-sdk/extension";

import { ghList, ghApi } from "./gh.mjs";
import { loadRemote, loadLocal } from "./patterns.mjs";
import { listDeployed, deployPatterns, deepLink } from "./scope.mjs";
import { renderHtml } from "./ui.mjs";

const extDir = path.dirname(fileURLToPath(import.meta.url));
function staticFile(name) {
    return readFileSync(path.join(extDir, name), "utf8");
}

const servers = new Map(); // instanceId -> { server, url }

function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
    res.end(body);
}

function readBody(req) {
    return new Promise((resolve) => {
        let data = "";
        req.on("data", (c) => (data += c));
        req.on("end", () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch {
                resolve({});
            }
        });
        req.on("error", () => resolve({}));
    });
}

async function handleApi(req, res, url) {
    try {
        if (req.method === "GET" && url.pathname === "/api/orgs") {
            const r = await ghList("/user/orgs");
            if (!r.ok) return sendJson(res, 200, { ok: false, error: r.error });
            const orgs = (r.data || []).map((o) => o.login).filter(Boolean).sort((a, b) => a.localeCompare(b));
            return sendJson(res, 200, { ok: true, orgs });
        }

        if (req.method === "GET" && url.pathname === "/api/repos") {
            const org = url.searchParams.get("org");
            if (!org) return sendJson(res, 200, { ok: false, error: "Missing org." });
            const q = (url.searchParams.get("q") || "").trim();
            const PER = 20;

            if (q) {
                // Type-ahead: GitHub Search API finds matching repos in one call,
                // no pagination through thousands of repos. `in:name fork:true`
                // searches names and includes forks; archived repos are included.
                const search = `org:${org} ${q} in:name fork:true`;
                const r = await ghApi(`/search/repositories?q=${encodeURIComponent(search)}&per_page=${PER}`);
                if (!r.ok) return sendJson(res, 200, { ok: false, error: r.error });
                const ql = q.toLowerCase();
                const repos = (r.data?.items || [])
                    .map((x) => ({ name: x.name, owner: x.owner?.login || org }))
                    // Prefer names that start with the query, then alphabetical.
                    .sort((a, b) => {
                        const ap = a.name.toLowerCase().startsWith(ql) ? 0 : 1;
                        const bp = b.name.toLowerCase().startsWith(ql) ? 0 : 1;
                        return ap - bp || a.name.localeCompare(b.name);
                    });
                return sendJson(res, 200, { ok: true, repos, searched: true });
            }

            // No query: fetch up to 100 in a single request (no --paginate). If the
            // org has fewer than 100 repos this is the complete list and the UI shows
            // a plain dropdown; at 100 there may be more, so the UI switches to
            // type-ahead search mode (the q branch above).
            const r = await ghApi(`/orgs/${encodeURIComponent(org)}/repos?per_page=100&sort=full_name&direction=asc`);
            if (!r.ok) return sendJson(res, 200, { ok: false, error: r.error });
            const list = Array.isArray(r.data) ? r.data : [];
            const repos = list
                .map((x) => ({ name: x.name, owner: x.owner?.login || org }))
                .sort((a, b) => a.name.localeCompare(b.name));
            return sendJson(res, 200, { ok: true, repos, complete: list.length < 100, searched: false });
        }

        if (req.method === "POST" && url.pathname === "/api/load-patterns") {
            const body = await readBody(req);
            const result = body.source === "local" ? await loadLocal(body) : await loadRemote(body);
            return sendJson(res, 200, result);
        }

        if (req.method === "POST" && url.pathname === "/api/list-deployed") {
            const { level, target } = await readBody(req);
            const r = await listDeployed(level, target || {});
            if (r.ok) {
                const enriched = r.patterns.map((p) => ({ ...p, html_url: deepLink(level, target || {}, p.id) }));
                return sendJson(res, 200, { ok: true, patterns: enriched });
            }
            return sendJson(res, 200, r);
        }

        if (req.method === "POST" && url.pathname === "/api/deploy") {
            const { level, target, patterns } = await readBody(req);
            const r = await deployPatterns(level, target || {}, patterns);
            if (r.ok) {
                const created = (r.created || []).map((p) => ({ ...p, html_url: deepLink(level, target || {}, p.id) }));
                return sendJson(res, 200, { ok: true, created });
            }
            return sendJson(res, 200, r);
        }

        return sendJson(res, 404, { ok: false, error: "Not found" });
    } catch (err) {
        return sendJson(res, 200, { ok: false, error: String(err && err.message ? err.message : err) });
    }
}

async function startServer(instanceId) {
    const server = createServer((req, res) => {
        const url = new URL(req.url, "http://127.0.0.1");
        if (url.pathname.startsWith("/api/")) {
            handleApi(req, res, url);
            return;
        }
        if (url.pathname === "/app.js") {
            res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
            res.end(staticFile("app.js"));
            return;
        }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(renderHtml());
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    return { server, url: `http://127.0.0.1:${port}/` };
}

const session = await joinSession({
    canvases: [
        createCanvas({
            id: "ss-custom-patterns",
            displayName: "Secret Scanning Custom Patterns",
            description: "Load patterns.yml configs and deploy secret-scanning custom patterns at the enterprise, org, or repo level.",
            actions: [
                {
                    name: "refresh",
                    description: "No-op refresh hook; the canvas UI drives all work via its own HTTP endpoints.",
                    handler: async (ctx) => ({ ok: true, instanceId: ctx.instanceId }),
                },
            ],
            open: async (ctx) => {
                let entry = servers.get(ctx.instanceId);
                if (!entry) {
                    entry = await startServer(ctx.instanceId);
                    servers.set(ctx.instanceId, entry);
                }
                return { title: "Secret Scanning Custom Patterns", url: entry.url };
            },
            onClose: async (ctx) => {
                const entry = servers.get(ctx.instanceId);
                if (entry) {
                    servers.delete(ctx.instanceId);
                    await new Promise((resolve) => entry.server.close(() => resolve()));
                }
            },
        }),
    ],
});

await session.log("ss-custom-patterns canvas ready", { ephemeral: true });
