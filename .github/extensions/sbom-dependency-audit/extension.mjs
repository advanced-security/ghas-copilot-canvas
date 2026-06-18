import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { CanvasError, createCanvas, joinSession } from "@github/copilot-sdk/extension";

const execFileAsync = promisify(execFile);
const API_BASE = "https://api.github.com";
const API_VERSION = "2022-11-28";
const DEFAULT_ORG = "adrienpessu-octodemo";
const DEFAULT_DEPENDENCY = "@antv/data-set";
const RETRIABLE_STATUSES = new Set([500, 502, 503, 504, 408]);
const instanceServers = new Map();
const tokenCache = { promise: null, value: null };

const session = await joinSession({
    canvases: [
        createCanvas({
            id: "sbom-dependency-audit",
            displayName: "SBOM Dependency Audit",
            description:
                "Scan a GitHub organization for an exact SBOM package match and show version, direct/transitive status, and dependency path.",
            inputSchema: {
                type: "object",
                properties: {
                    org: {
                        type: "string",
                        minLength: 1,
                        default: DEFAULT_ORG,
                    },
                    dependency: {
                        type: "string",
                        minLength: 1,
                        default: DEFAULT_DEPENDENCY,
                    },
                },
                additionalProperties: false,
            },
            actions: [
                {
                    name: "run_scan",
                    description: "Run a fresh SBOM scan and return the Markdown report.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            org: { type: "string", minLength: 1 },
                            dependency: { type: "string", minLength: 1 },
                        },
                        additionalProperties: false,
                    },
                    handler: async (ctx) => {
                        const input = normalizeInput(ctx.input);
                        try {
                            const result = await scanOrganization(input.org, input.dependency);
                            const markdown = renderMarkdown(result);
                            return {
                                org: input.org,
                                dependency: input.dependency,
                                scannedRepositories: result.totalRepositories,
                                markdown,
                            };
                        } catch (error) {
                            throw new CanvasError("scan_failed", explainScanError(error, input.org));
                        }
                    },
                },
            ],
            open: async (ctx) => {
                const input = normalizeInput(ctx.input);
                const entry = await getInstanceEntry(ctx.instanceId, input);
                entry.input = input;
                await preloadEntry(ctx.instanceId, entry);
                await persistEntry(ctx.instanceId, entry);
                return {
                    title: `SBOM audit: ${input.org} / ${input.dependency}`,
                    status: entry.status === "running" ? "Scanning..." : "Ready",
                    url: entry.url,
                };
            },
            onClose: async (ctx) => {
                const entry = instanceServers.get(ctx.instanceId);
                if (!entry) {
                    return;
                }

                instanceServers.delete(ctx.instanceId);
                await new Promise((resolve) => entry.server.close(() => resolve()));
            },
        }),
    ],
});

const workspaceStateDir = session.workspacePath
    ? join(session.workspacePath, ".sbom-dependency-audit")
    : null;

function normalizeInput(input) {
    return {
        org: normalizeNonEmptyString(input?.org, DEFAULT_ORG),
        dependency: normalizeNonEmptyString(input?.dependency, DEFAULT_DEPENDENCY),
    };
}

function normalizeNonEmptyString(value, fallback) {
    const text = typeof value === "string" ? value.trim() : "";
    return text || fallback;
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function escapeMarkdown(value) {
    return String(value).replaceAll("|", "\\|");
}

function jsonResponse(res, status, payload) {
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
    });
    res.end(JSON.stringify(payload));
}

function textResponse(res, status, text, contentType = "text/plain; charset=utf-8") {
    res.writeHead(status, {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
    });
    res.end(text);
}

function errorMessage(error) {
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return String(error ?? "Unknown error");
}

function explainScanError(error, org) {
    const message = errorMessage(error);
    const normalized = message.toLowerCase();

    if (
        normalized.includes("status 401") ||
        normalized.includes("status 403") ||
        normalized.includes("rate limit") ||
        normalized.includes("bad credentials") ||
        normalized.includes("requires authentication")
    ) {
        return `${message}. GitHub authentication may be missing or expired. Run 'gh auth status' and 'gh auth login' (or set GITHUB_TOKEN), then retry.`;
    }

    if (normalized.includes("failed to list repositories") && normalized.includes("status 404")) {
        return `${message}. Verify the organization '${org}' exists and that your token can access it.`;
    }

    if (
        normalized.includes("fetch failed") ||
        normalized.includes("etimedout") ||
        normalized.includes("econnreset") ||
        normalized.includes("eai_again") ||
        normalized.includes("enotfound") ||
        normalized.includes("econnrefused")
    ) {
        return `${message}. Network access to the GitHub API failed; check connectivity and retry.`;
    }

    return message;
}

async function readRequestBody(req) {
    const chunks = [];
    for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    return raw ? JSON.parse(raw) : {};
}

async function resolveToken() {
    if (tokenCache.value !== null) {
        return tokenCache.value;
    }
    if (!tokenCache.promise) {
        tokenCache.promise = (async () => {
            for (const key of ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_API_TOKEN"]) {
                if (process.env[key]) {
                    return process.env[key];
                }
            }

            try {
                const { stdout } = await execFileAsync("gh", ["auth", "token"], {
                    encoding: "utf8",
                    timeout: 10_000,
                });
                return stdout.trim() || null;
            } catch {
                return null;
            }
        })();
    }

    tokenCache.value = await tokenCache.promise;
    return tokenCache.value;
}

function requestHeaders(token) {
    const headers = {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    };
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    return headers;
}

function shouldRetry(error) {
    const code = error?.code;
    return (
        error?.name === "AbortError" ||
        code === "ETIMEDOUT" ||
        code === "ECONNRESET" ||
        code === "EAI_AGAIN" ||
        code === "ENOTFOUND" ||
        code === "ECONNREFUSED"
    );
}

async function fetchJson(url, token, options = {}) {
    const timeoutMs = options.timeoutMs ?? 20_000;
    const method = options.method ?? "GET";
    const body = options.body;
    const headers = {
        ...requestHeaders(token),
        ...(options.headers || {}),
    };

    let attempt = 0;
    for (;;) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const response = await fetch(url, {
                method,
                headers,
                body,
                signal: controller.signal,
            });

            const text = await response.text();
            let payload = {};
            if (text) {
                try {
                    payload = JSON.parse(text);
                } catch {
                    payload = { message: text.slice(0, 500) };
                }
            }
            if (response.ok) {
                return { status: response.status, payload };
            }

            if (RETRIABLE_STATUSES.has(response.status)) {
                attempt += 1;
                await delay(Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5)));
                continue;
            }

            return { status: response.status, payload };
        } catch (error) {
            if (!shouldRetry(error)) {
                throw error;
            }

            attempt += 1;
            await delay(Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5)));
        } finally {
            clearTimeout(timer);
        }
    }
}

async function listRepositories(org, token) {
    const repositories = [];
    let page = 1;

    for (;;) {
        const query = new URLSearchParams({
            per_page: "100",
            type: "all",
            page: String(page),
        });
        const url = `${API_BASE}/orgs/${encodeURIComponent(org)}/repos?${query.toString()}`;
        const { status, payload } = await fetchJson(url, token);
        if (status !== 200) {
            throw new Error(
                `Failed to list repositories for '${org}' (status ${status}): ${payload?.message ?? "unknown error"}`
            );
        }

        if (!Array.isArray(payload) || payload.length === 0) {
            break;
        }

        for (const repo of payload) {
            if (repo?.name) {
                repositories.push(repo.name);
            }
        }

        page += 1;
    }

    return repositories;
}

function versionFromPurl(referenceLocator, dependency) {
    const decoded = decodeURIComponent(referenceLocator || "");
    if (!decoded.startsWith("pkg:npm/")) {
        return null;
    }

    const packageWithVersion = decoded.slice("pkg:npm/".length).split("?", 1)[0];
    const marker = `${dependency}@`;
    if (packageWithVersion.startsWith(marker)) {
        return packageWithVersion.slice(marker.length);
    }

    return null;
}

function packageVersion(packageItem, dependencyName) {
    const version = packageItem?.versionInfo ?? packageItem?.version;
    if (version) {
        return String(version);
    }

    for (const externalRef of packageItem?.externalRefs ?? []) {
        const purlVersion = versionFromPurl(String(externalRef?.referenceLocator ?? ""), dependencyName);
        if (purlVersion) {
            return purlVersion;
        }
    }

    return "(no version in SBOM)";
}

function packageLabel(packageItem) {
    const name = String(packageItem?.name ?? packageItem?.SPDXID ?? "(unknown package)");
    const version = packageVersion(packageItem, name);
    return version === "(no version in SBOM)" ? name : `${name}@${version}`;
}

function dependencyEdges(sbom) {
    const edges = new Map();
    for (const relationship of sbom?.relationships ?? []) {
        if (relationship?.relationshipType !== "DEPENDS_ON") {
            continue;
        }

        const source = relationship?.spdxElementId;
        const target = relationship?.relatedSpdxElement;
        if (!source || !target) {
            continue;
        }

        const sourceKey = String(source);
        const targetValue = String(target);
        const list = edges.get(sourceKey) ?? [];
        list.push(targetValue);
        edges.set(sourceKey, list);
    }

    return edges;
}

function dependencyRoots(sbom, edges) {
    const packageIds = new Set(
        (sbom?.packages ?? [])
            .map((packageItem) => packageItem?.SPDXID)
            .filter(Boolean)
            .map(String)
    );

    const roots = [...edges.keys()].filter((source) => !packageIds.has(source)).sort();
    return roots.length ? roots : [...edges.keys()].sort();
}

function shortestDependencyPath(sbom, targetId) {
    const edges = dependencyEdges(sbom);
    const queue = dependencyRoots(sbom, edges).map((root) => [root]);
    const visited = new Set();

    while (queue.length) {
        const path = queue.shift();
        const current = path[path.length - 1];
        if (current === targetId) {
            return path;
        }

        if (visited.has(current)) {
            continue;
        }
        visited.add(current);

        for (const dependency of edges.get(current) ?? []) {
            queue.push([...path, dependency]);
        }
    }

    return null;
}

function dependencyPathDetails(sbom, targetPackage) {
    const targetId = targetPackage?.SPDXID;
    const version = packageVersion(targetPackage, String(targetPackage?.name ?? ""));
    if (!targetId) {
        return {
            version,
            dependencyType: "Unknown",
            pathFromDirectDependency: ["(package has no SPDXID)"],
        };
    }

    const packagesById = new Map(
        (sbom?.packages ?? [])
            .filter((packageItem) => packageItem?.SPDXID)
            .map((packageItem) => [String(packageItem.SPDXID), packageItem])
    );

    const path = shortestDependencyPath(sbom, String(targetId));
    if (!path) {
        return {
            version,
            dependencyType: "Unknown",
            pathFromDirectDependency: ["(path not available in SBOM)"],
        };
    }

    const pathFromDirectDependency = path.slice(1);
    return {
        version,
        dependencyType: path.length <= 2 ? "Direct" : "Transitive",
        pathFromDirectDependency: pathFromDirectDependency.map((node) =>
            packagesById.has(node) ? packageLabel(packagesById.get(node)) : node
        ),
    };
}

function dependencyMatches(sbom, dependency) {
    return (sbom?.packages ?? [])
        .filter((packageItem) => packageItem?.name === dependency)
        .map((packageItem) => dependencyPathDetails(sbom, packageItem))
        .sort((left, right) => {
            const leftPath = left.pathFromDirectDependency.join(" -> ");
            const rightPath = right.pathFromDirectDependency.join(" -> ");
            return left.version.localeCompare(right.version) || leftPath.localeCompare(rightPath);
        });
}

async function searchInSbom(org, repository, dependency, token) {
    const url = `${API_BASE}/repos/${encodeURIComponent(org)}/${encodeURIComponent(repository)}/dependency-graph/sbom`;
    const { status, payload } = await fetchJson(url, token);
    const fullRepository = `${org}/${repository}`;

    if (status === 404) {
        return {
            matches: [],
            disabled: {
                repository: fullRepository,
                gh_owner: org,
                status,
                message: "Dependency Graph not enabled",
            },
            error: null,
        };
    }

    if (status !== 200) {
        return {
            matches: [],
            disabled: null,
            error: {
                repository: fullRepository,
                gh_owner: org,
                status,
                message: payload?.message ?? "unknown error",
            },
        };
    }

    const sbom = payload?.sbom ?? payload;
    return {
        matches: dependencyMatches(sbom, dependency),
        disabled: null,
        error: null,
    };
}

async function scanOrganization(org, dependency) {
    const token = await resolveToken();
    const repositories = await listRepositories(org, token);
    const matches = [];
    const disabled = [];
    const errors = [];

    for (const repository of repositories) {
        const result = await searchInSbom(org, repository, dependency, token);
        if (result.disabled) {
            disabled.push(result.disabled);
            continue;
        }

        if (result.error) {
            errors.push(result.error);
            continue;
        }

        if (result.matches.length) {
            matches.push({
                repository: `${org}/${repository}`,
                gh_owner: org,
                dependencies: result.matches,
            });
        }
    }

    matches.sort((left, right) => left.repository.localeCompare(right.repository));
    disabled.sort((left, right) => left.repository.localeCompare(right.repository));
    errors.sort((left, right) => left.repository.localeCompare(right.repository));

    return {
        org,
        dependency,
        totalRepositories: repositories.length,
        matches,
        disabled,
        errors,
    };
}

function renderActionPlan(result) {
    const dependency = escapeMarkdown(result.dependency);
    const lines = [
        "",
        "## Security engineer action plan",
        "",
        "| Priority | Action | Why |",
        "|---:|---|---|",
        `| P0 | Confirm whether \`${dependency}\` and the affected versions are in scope. | Prevents unnecessary remediation when the package name matches but the vulnerable version does not. |`,
        `| P1 | Notify owners of repositories listed above and include the path from direct dependency. | Direct owners can patch direct dependencies first; service owners can validate runtime exposure. |`,
        `| P1 | For Direct matches, update or remove the dependency and rebuild affected artifacts. | Direct dependencies are controlled by the repository. |`,
        `| P2 | For Transitive matches, change the first package in the path from direct dependency. | Transitive exposure is remediated by changing the package that introduces it. |`,
        `| P2 | Re-run the SBOM audit after remediation and keep the before/after report. | Confirms closure across the scanned estate. |`,
    ];

    if (result.disabled.length || result.errors.length) {
        lines.push(
            `| P2 | Resolve repositories listed under Dependency Graph not enabled or SBOM errors, then re-run the audit. | Do not claim complete coverage while repositories could not be confirmed. |`
        );
    }

    return lines;
}

function renderMarkdown(result) {
    const lines = [
        `# SBOM dependency report: \`${escapeMarkdown(result.dependency)}\``,
        "",
        `Organization: \`github.com/${escapeMarkdown(result.org)}\``,
        "",
    ];

    if (result.matches.length) {
        lines.push(
            "| Repository | gh_owner | Version | Dependency type | Path from direct dependency |",
            "|---|---|---:|---|---|"
        );

        for (const match of result.matches) {
            for (const dependencyMatch of match.dependencies) {
                const path = dependencyMatch.pathFromDirectDependency
                    .map((item) => `\`${escapeMarkdown(item)}\``)
                    .join(" -> ");
                lines.push(
                    `| \`${escapeMarkdown(match.repository)}\` | \`${escapeMarkdown(match.gh_owner)}\` | \`${escapeMarkdown(dependencyMatch.version)}\` | ${dependencyMatch.dependencyType} | ${path} |`
                );
            }
        }
    } else {
        lines.push(`No SBOM occurrence of \`${escapeMarkdown(result.dependency)}\` was found.`);
    }

    lines.push(...renderActionPlan(result));
    lines.push(
        "",
        `Scanned ${result.totalRepositories} repositories via the GitHub Dependency Graph SBOM REST endpoint.`
    );

    if (result.disabled.length) {
        lines.push(
            `${result.disabled.length} repositories could not be confirmed because the Dependency Graph is not enabled.`
        );
    }

    if (result.errors.length) {
        lines.push(`${result.errors.length} repositories returned SBOM errors.`);
    }

    if (result.disabled.length) {
        lines.push(
            "",
            "## Dependency Graph not enabled",
            "",
            "| Repository | gh_owner | Status |",
            "|---|---|---|"
        );
        for (const entry of result.disabled) {
            lines.push(
                `| \`${escapeMarkdown(entry.repository)}\` | \`${escapeMarkdown(entry.gh_owner)}\` | Dependency Graph not enabled |`
            );
        }
    }

    if (result.errors.length) {
        lines.push(
            "",
            "## SBOM errors",
            "",
            "| Repository | gh_owner | Status | Message |",
            "|---|---|---:|---|"
        );
        for (const entry of result.errors) {
            lines.push(
                `| \`${escapeMarkdown(entry.repository)}\` | \`${escapeMarkdown(entry.gh_owner)}\` | ${entry.status} | ${escapeMarkdown(entry.message)} |`
            );
        }
    }

    return lines.join("\n") + "\n";
}

function renderPage(state) {
    const initial = JSON.stringify(state).replaceAll("<", "\\u003c");
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SBOM Dependency Audit</title>
    <style>
      :root {
        color-scheme: light dark;
        --panel: var(--background-color-default, #ffffff);
        --panel-border: var(--border-color-default, #d0d7de);
        --text: var(--text-color-default, #24292f);
        --muted: var(--text-color-muted, #57606a);
        --accent: var(--color-focus-outline, #0969da);
        --surface: color-mix(in srgb, var(--panel) 92%, var(--panel-border) 8%);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        padding: 16px;
        background: var(--panel);
        color: var(--text);
        font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
        font-size: var(--text-body-medium, 14px);
        line-height: var(--leading-body-medium, 20px);
      }
      h1 { margin: 0 0 4px; font-size: 20px; }
      .muted { color: var(--muted); }
      .toolbar, .summary, .section { margin-top: 16px; padding: 12px; border: 1px solid var(--panel-border); border-radius: 12px; background: var(--surface); }
      .grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; align-items: end; }
      label { display: block; font-weight: 600; margin-bottom: 6px; }
      input, button { width: 100%; border-radius: 10px; border: 1px solid var(--panel-border); background: var(--panel); color: var(--text); padding: 10px 12px; font: inherit; }
      button { cursor: pointer; background: var(--accent); border-color: var(--accent); color: white; font-weight: 600; }
      button[disabled] { opacity: .6; cursor: progress; }
      table { width: 100%; border-collapse: collapse; margin-top: 8px; }
      th, td { border-top: 1px solid var(--panel-border); padding: 8px 6px; text-align: left; vertical-align: top; }
      th { font-weight: 600; }
      .status { margin-left: 8px; font-weight: 600; }
      .pill { display: inline-block; margin-left: 8px; padding: 2px 8px; border-radius: 999px; background: color-mix(in srgb, var(--accent) 15%, transparent); color: var(--accent); font-size: 12px; }
      .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
      .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }
      .card { border: 1px solid var(--panel-border); border-radius: 12px; padding: 12px; background: var(--panel); }
      .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
      .card .value { font-size: 22px; font-weight: 700; margin-top: 6px; }
      .section-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      .empty { padding: 12px; border: 1px dashed var(--panel-border); border-radius: 10px; color: var(--muted); margin-top: 8px; }
      .error-banner {
        margin-top: 16px;
        border-radius: 12px;
        border: 1px solid #cf222e;
        background: color-mix(in srgb, #cf222e 12%, transparent);
        color: #cf222e;
        padding: 12px;
        white-space: pre-wrap;
      }
      .path { font-family: var(--font-mono, ui-monospace, SFMono-Regular, Consolas, monospace); font-size: 12px; }
      @media (max-width: 900px) { .grid, .cards { grid-template-columns: 1fr; } }
    </style>
  </head>
  <body>
    <h1>SBOM Dependency Audit</h1>
    <div class="muted">Scan a GitHub organization for an exact dependency match from Dependency Graph SBOM data.</div>

    <form class="toolbar" id="scan-form">
      <div class="grid">
        <div>
          <label for="org">Organization</label>
          <input id="org" name="org" spellcheck="false" />
        </div>
        <div>
          <label for="dependency">Dependency</label>
          <input id="dependency" name="dependency" spellcheck="false" />
        </div>
        <div>
          <button id="scan-button" type="submit">Scan</button>
        </div>
      </div>
      <div class="row" style="margin-top: 10px;">
        <span class="muted">The panel preloads the current scan result on open.</span>
        <span class="status" id="status"></span>
      </div>
    </form>

    <div id="error-banner" class="error-banner" hidden></div>
    <div class="summary" id="summary"></div>
    <div class="section" id="matches-section"></div>
    <div class="section" id="disabled-section"></div>
    <div class="section" id="errors-section"></div>

    <script>
      const initialState = ${initial};
      const $ = (id) => document.getElementById(id);
      const orgInput = $("org");
      const dependencyInput = $("dependency");
      const summary = $("summary");
      const status = $("status");
      const scanButton = $("scan-button");
      const errorBanner = $("error-banner");
      const matchesSection = $("matches-section");
      const disabledSection = $("disabled-section");
      const errorsSection = $("errors-section");

      function escapeHtml(value) {
        return String(value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;");
      }

      function setStatus(text) {
        status.textContent = text || "";
      }

      function errorMessage(error) {
        if (error && typeof error.message === "string" && error.message) {
          return error.message;
        }
        return String(error || "Unknown error");
      }

      function renderErrorBanner(message) {
        if (message) {
          errorBanner.hidden = false;
          errorBanner.textContent = message;
          return;
        }
        errorBanner.hidden = true;
        errorBanner.textContent = "";
      }

      function renderSummary(state) {
        const result = state.result || {};
        const cards = [
          ["Repositories scanned", String(result.totalRepositories ?? 0)],
          ["Matches", String(result.matches?.length ?? 0)],
          ["Dependency Graph off", String(result.disabled?.length ?? 0)],
          ["SBOM errors", String(result.errors?.length ?? 0)],
        ];

        summary.innerHTML =
          '<div class="section-title"><strong>Current report</strong><span class="pill">' +
          escapeHtml(state.org) +
          ' / ' +
          escapeHtml(state.dependency) +
          '</span></div>' +
          '<div class="cards">' +
          cards
            .map(function (card) {
              return '<div class="card"><div class="label">' + escapeHtml(card[0]) + '</div><div class="value">' + escapeHtml(card[1]) + '</div></div>';
            })
            .join("") +
          '</div>';
      }

      function renderMatches(result) {
        const matches = result.matches || [];
        if (!matches.length) {
          matchesSection.innerHTML =
            '<div class="section-title"><strong>Matches</strong></div>' +
            '<div class="empty">No exact dependency match found.</div>';
          return;
        }

        const rows = matches
          .flatMap(function (match) {
            return match.dependencies.map(function (dependencyMatch) {
              const path = (dependencyMatch.pathFromDirectDependency || [])
                .map(function (item) {
                  return '<span class="path">' + escapeHtml(item) + '</span>';
                })
                .join(' &rarr; ');
              return '<tr>' +
                '<td>' + escapeHtml(match.repository) + '</td>' +
                '<td>' + escapeHtml(dependencyMatch.version) + '</td>' +
                '<td>' + escapeHtml(dependencyMatch.dependencyType) + '</td>' +
                '<td>' + path + '</td>' +
              '</tr>';
            });
          })
          .join("");

        matchesSection.innerHTML =
          '<div class="section-title"><strong>Matches</strong><span class="pill">' + escapeHtml(String(matches.length)) + ' repositories</span></div>' +
          '<table><thead><tr><th>Repository</th><th>Version</th><th>Type</th><th>Path from direct dependency</th></tr></thead><tbody>' +
          rows +
          '</tbody></table>';
      }

      function renderSimpleSection(section, title, items, emptyText, columns, rowBuilder) {
        if (!items || !items.length) {
          section.innerHTML =
            '<div class="section-title"><strong>' + escapeHtml(title) + '</strong></div>' +
            '<div class="empty">' + escapeHtml(emptyText) + '</div>';
          return;
        }

        const rows = items.map(rowBuilder).join("");
        section.innerHTML =
          '<div class="section-title"><strong>' + escapeHtml(title) + '</strong><span class="pill">' + escapeHtml(String(items.length)) + '</span></div>' +
          '<table><thead><tr>' +
          columns.map(function (column) { return '<th>' + escapeHtml(column) + '</th>'; }).join("") +
          '</tr></thead><tbody>' +
          rows +
          '</tbody></table>';
      }

      function renderState(state) {
        const result = state.result || { matches: [], disabled: [], errors: [] };
        orgInput.value = state.org || "";
        dependencyInput.value = state.dependency || "";
        renderSummary(state);
        renderMatches(result);
        renderSimpleSection(
          disabledSection,
          "Dependency Graph not enabled",
          result.disabled || [],
          "Every repository returned SBOM data.",
          ["Repository", "gh_owner", "Status"],
          function (item) {
            return '<tr><td>' + escapeHtml(item.repository) + '</td><td>' + escapeHtml(item.gh_owner) + '</td><td>' + escapeHtml(item.message || "Dependency Graph not enabled") + '</td></tr>';
          }
        );
        renderSimpleSection(
          errorsSection,
          "SBOM errors",
          result.errors || [],
          "No SBOM errors were returned.",
          ["Repository", "gh_owner", "Status", "Message"],
          function (item) {
            return '<tr><td>' + escapeHtml(item.repository) + '</td><td>' + escapeHtml(item.gh_owner) + '</td><td>' + escapeHtml(item.status) + '</td><td>' + escapeHtml(item.message) + '</td></tr>';
          }
        );
        renderErrorBanner(state.error || "");
        setStatus(state.status === "running" ? "Scanning..." : (state.error || "Ready"));
      }

      async function scan() {
        scanButton.disabled = true;
        setStatus("Scanning...");
        try {
          const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              org: orgInput.value.trim(),
              dependency: dependencyInput.value.trim(),
            }),
          });
          const payload = await response.json();
          if (!response.ok) {
            throw new Error(payload.error || "Scan failed");
          }
          renderState(payload);
        } catch (error) {
          setStatus(errorMessage(error));
          renderErrorBanner(errorMessage(error));
        } finally {
          scanButton.disabled = false;
        }
      }

      async function loadState() {
        try {
          const response = await fetch("/state");
          const state = await response.json();
          renderState(state);
        } catch (error) {
          setStatus(errorMessage(error));
          renderErrorBanner(errorMessage(error));
        }
      }

      document.getElementById("scan-form").addEventListener("submit", function (event) {
        event.preventDefault();
        scan();
      });

      renderState(initialState);
      loadState();
    </script>
  </body>
</html>`;
}

async function ensureWorkspaceDir() {
    if (!workspaceStateDir) {
        return null;
    }
    await fs.mkdir(workspaceStateDir, { recursive: true });
    return workspaceStateDir;
}

function stateFilePath(instanceId) {
    return workspaceStateDir ? join(workspaceStateDir, `${instanceId}.json`) : null;
}

async function loadPersistedEntry(instanceId) {
    const filePath = stateFilePath(instanceId);
    if (!filePath) {
        return null;
    }

    try {
        const raw = await fs.readFile(filePath, "utf8");
        return JSON.parse(raw);
    } catch {
        return null;
    }
}

async function persistEntry(instanceId, entry) {
    const filePath = stateFilePath(instanceId);
    if (!filePath) {
        return;
    }

    await ensureWorkspaceDir();
    const persisted = {
        input: entry.input,
        status: entry.status,
        markdown: entry.markdown || "",
        result: entry.result || null,
        error: entry.error || null,
        updatedAt: new Date().toISOString(),
    };
    await fs.writeFile(filePath, JSON.stringify(persisted, null, 2), "utf8");
}

async function preloadEntry(instanceId, entry) {
    if (entry.result || entry.status === "running") {
        return;
    }

    entry.status = "running";
    entry.error = null;
    await persistEntry(instanceId, entry);

    try {
        const result = await scanOrganization(entry.input.org, entry.input.dependency);
        entry.result = result;
        entry.markdown = renderMarkdown(result);
        entry.status = "idle";
        entry.error = null;
        await persistEntry(instanceId, entry);
    } catch (error) {
        entry.status = "idle";
        entry.error = explainScanError(error, entry.input.org);
        await persistEntry(instanceId, entry);
    }
}

async function getInstanceEntry(instanceId, input) {
    let entry = instanceServers.get(instanceId);
    if (entry) {
        return entry;
    }

    const persisted = await loadPersistedEntry(instanceId);
    entry = {
        input: persisted?.input ? normalizeInput(persisted.input) : input,
        status: persisted?.status ?? "idle",
        markdown: persisted?.markdown ?? "",
        result: persisted?.result ?? null,
        error: persisted?.error ?? null,
        url: null,
        server: null,
    };

    const server = createServer(async (req, res) => {
        const url = new URL(req.url, "http://127.0.0.1");

        if (req.method === "GET" && url.pathname === "/") {
            textResponse(res, 200, renderPage(await serializeEntry(instanceId, entry)), "text/html; charset=utf-8");
            return;
        }

        if (req.method === "GET" && url.pathname === "/state") {
            jsonResponse(res, 200, await serializeEntry(instanceId, entry));
            return;
        }

        if (req.method === "POST" && url.pathname === "/scan") {
            try {
                const body = await readRequestBody(req);
                const nextInput = normalizeInput({
                    org: body.org ?? entry.input.org,
                    dependency: body.dependency ?? entry.input.dependency,
                });
                entry.input = nextInput;
                entry.status = "running";
                entry.error = null;
                await persistEntry(instanceId, entry);

                const result = await scanOrganization(nextInput.org, nextInput.dependency);
                const markdown = renderMarkdown(result);
                entry.status = "idle";
                entry.result = result;
                entry.markdown = markdown;
                await persistEntry(instanceId, entry);
                jsonResponse(res, 200, await serializeEntry(instanceId, entry));
            } catch (error) {
                entry.status = "idle";
                entry.error = explainScanError(error, entry.input.org);
                await persistEntry(instanceId, entry);
                jsonResponse(res, 500, {
                    error: entry.error,
                });
            }
            return;
        }

        if (req.method === "GET" && url.pathname === "/report.md") {
            textResponse(
                res,
                200,
                entry.markdown ||
                    renderMarkdown({
                        org: entry.input.org,
                        dependency: entry.input.dependency,
                        totalRepositories: entry.result?.totalRepositories ?? 0,
                        matches: entry.result?.matches ?? [],
                        disabled: entry.result?.disabled ?? [],
                        errors: entry.result?.errors ?? [],
                    }),
                "text/markdown; charset=utf-8"
            );
            return;
        }

        jsonResponse(res, 404, { error: "Not found" });
    });

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;

    entry.server = server;
    entry.url = `http://127.0.0.1:${port}/`;
    instanceServers.set(instanceId, entry);
    return entry;
}

async function serializeEntry(instanceId, entry) {
    return {
        instanceId,
        org: entry.input.org,
        dependency: entry.input.dependency,
        status: entry.status,
        markdown: entry.markdown || "",
        result: entry.result,
        error: entry.error,
    };
}
