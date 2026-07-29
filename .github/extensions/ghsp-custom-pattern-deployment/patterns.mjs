// Load and normalize `patterns.yml` files from a remote repo or a local path
// into deployable custom-pattern objects.

import { promises as fs } from "node:fs";
import path from "node:path";
import yaml from "./js-yaml.mjs";
import { ghApi, ghRawFile } from "./gh.mjs";

function clean(v) {
    if (v == null) return "";
    return String(v).replace(/\r\n/g, "\n").replace(/\n+$/, "").trim();
}

function cleanList(v) {
    if (!v) return [];
    const arr = Array.isArray(v) ? v : [v];
    return arr.map((x) => clean(x)).filter((x) => x.length > 0);
}

// Normalize test data. `data` is preserved as-is (only CRLF→LF and trailing
// newlines stripped) because start/end offsets index into it. `test` may be a
// single mapping or a list of them; offsets are optional.
function toOffset(v) {
    if (v == null || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
}

function normalizeTests(t) {
    if (!t) return [];
    const arr = Array.isArray(t) ? t : [t];
    return arr
        .map((tc) => {
            if (tc == null) return null;
            if (typeof tc === "string") {
                const data = String(tc).replace(/\r\n/g, "\n").replace(/\n+$/, "");
                return data ? { data, start: null, end: null } : null;
            }
            if (typeof tc !== "object") return null;
            const data = tc.data != null ? String(tc.data).replace(/\r\n/g, "\n").replace(/\n+$/, "") : "";
            if (!data) return null;
            return { data, start: toOffset(tc.start_offset), end: toOffset(tc.end_offset) };
        })
        .filter(Boolean);
}

// Turn one parsed YAML document into a normalized config group.
function normalizeDoc(doc, file) {
    if (!doc || typeof doc !== "object") return null;
    const patterns = Array.isArray(doc.patterns) ? doc.patterns : [];
    const out = patterns
        .map((p) => {
            const regex = p.regex || {};
            const deploy = {
                name: clean(p.name),
                pattern: clean(regex.pattern),
                start_delimiter: clean(regex.start),
                end_delimiter: clean(regex.end),
                must_match: cleanList(regex.additional_match),
                must_not_match: cleanList(regex.additional_not_match),
            };
            return {
                name: deploy.name,
                type: p.type ? String(p.type) : "",
                experimental: Boolean(p.experimental),
                comments: cleanList(p.comments),
                version: regex.version != null ? String(regex.version) : "",
                tests: normalizeTests(p.test),
                deploy,
            };
        })
        .filter((p) => p.name && p.deploy.pattern);
    if (out.length === 0) return null;
    return {
        file,
        name: clean(doc.name) || file,
        patterns: out,
    };
}

function parseYamlSafe(text, file) {
    try {
        return normalizeDoc(yaml.load(text), file);
    } catch (err) {
        const msg = err && err.message ? err.message : String(err);
        return { file, name: file, error: `YAML parse error: ${msg}`, patterns: [] };
    }
}

// ---- Remote loading ---------------------------------------------------------

async function resolveRef(owner, repo, ref) {
    if (ref && ref.trim()) return ref.trim();
    const res = await ghApi(`/repos/${owner}/${repo}`);
    return res.ok && res.data?.default_branch ? res.data.default_branch : "main";
}

export async function loadRemote({ repo, ref }) {
    const [owner, name] = String(repo || "").split("/");
    if (!owner || !name) return { ok: false, error: "Repository must be in 'owner/repo' form." };
    const resolvedRef = await resolveRef(owner, name, ref);

    const tree = await ghApi(`/repos/${owner}/${name}/git/trees/${encodeURIComponent(resolvedRef)}?recursive=1`);
    if (!tree.ok) {
        return { ok: false, error: `Could not read repo tree (${tree.status}): ${tree.error}` };
    }
    const entries = Array.isArray(tree.data?.tree) ? tree.data.tree : [];
    // GitHub caps the recursive tree at 100,000 entries / 7MB; beyond that it sets
    // `truncated: true` and silently omits the rest, which could hide patterns.yml
    // files deep in a very large repo without any indication in the UI.
    const truncated = !!tree.data?.truncated;
    const warning = truncated
        ? "The repository tree was truncated by GitHub (100,000+ entries or 7MB+). Some patterns.yml files may not have been found; consider pointing at a subdirectory or a smaller ref."
        : undefined;
    const ymlPaths = entries
        .filter((e) => e.type === "blob" && /(^|\/)patterns\.ya?ml$/i.test(e.path))
        .map((e) => e.path)
        .sort();
    if (ymlPaths.length === 0) {
        return {
            ok: false,
            error: truncated
                ? "No patterns.yml files found before GitHub truncated the repo tree (100,000+ entries or 7MB+). There may be more; try a subdirectory or a smaller ref."
                : "No patterns.yml files found in that repo/ref.",
        };
    }

    const configs = [];
    // Limited concurrency to be gentle on the API.
    const queue = [...ymlPaths];
    async function worker() {
        while (queue.length) {
            const p = queue.shift();
            const raw = await ghRawFile(owner, name, p, resolvedRef);
            if (!raw.ok) {
                configs.push({ file: p, name: p, error: raw.error, patterns: [] });
                continue;
            }
            const cfg = parseYamlSafe(raw.content, p);
            if (cfg) configs.push(cfg);
        }
    }
    await Promise.all([worker(), worker(), worker(), worker()]);
    configs.sort((a, b) => a.file.localeCompare(b.file));
    return { ok: true, source: { type: "remote", repo: `${owner}/${name}`, ref: resolvedRef }, configs, warning };
}

// ---- Local loading ----------------------------------------------------------

async function walk(dir, acc = []) {
    let entries;
    try {
        entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
        return acc;
    }
    for (const e of entries) {
        if (e.name === ".git" || e.name === "node_modules") continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) await walk(full, acc);
        else if (/^patterns\.ya?ml$/i.test(e.name)) acc.push(full);
    }
    return acc;
}

export async function loadLocal({ localPath }) {
    const root = String(localPath || "").trim();
    if (!root) return { ok: false, error: "Local path is required." };
    let stat;
    try {
        stat = await fs.stat(root);
    } catch {
        return { ok: false, error: `Path not found: ${root}` };
    }
    let files = [];
    if (stat.isDirectory()) files = await walk(root);
    else if (/patterns\.ya?ml$/i.test(root)) files = [root];
    if (files.length === 0) return { ok: false, error: "No patterns.yml files found at that path." };

    const configs = [];
    for (const f of files.sort()) {
        try {
            const text = await fs.readFile(f, "utf8");
            const rel = path.relative(root, f) || path.basename(f);
            const cfg = parseYamlSafe(text, rel.split(path.sep).join("/"));
            if (cfg) configs.push(cfg);
        } catch (err) {
            configs.push({ file: f, name: f, error: String(err.message), patterns: [] });
        }
    }
    return { ok: true, source: { type: "local", path: root }, configs };
}
