// CodeQL Config Builder iframe app

const CODEQL_LANGUAGES = [
  "actions",
  "c-cpp",
  "csharp",
  "go",
  "java-kotlin",
  "javascript-typescript",
  "python",
  "ruby",
  "rust",
  "swift",
];

const CODEQL_QUERY_SUITES = [
  "security-extended",
  "security-and-quality",
  "security-experimental",
  "code-scanning",
  "code-quality",
];

const CODEQL_OFFICIAL_PACKS = [
  "codeql/actions-queries",
  "codeql/cpp-queries",
  "codeql/csharp-queries",
  "codeql/go-queries",
  "codeql/java-queries",
  "codeql/javascript-queries",
  "codeql/python-queries",
  "codeql/ruby-queries",
  "codeql/rust-queries",
  "codeql/swift-queries",
];

const CODEQL_FILTER_KEYS = [
  "id", "tags", "kind", "precision", "problem.severity", "security-severity",
];

const CODEQL_FILTER_VALUES_BY_KEY = {
  tags: ["security", "correctness", "maintainability", "reliability"],
  kind: ["problem", "path-problem", "alert", "diagnostic"],
  precision: ["very-high", "high", "medium", "low"],
  "problem.severity": ["error", "warning", "recommendation"],
  "security-severity": ["9.0", "7.0", "4.0", "0.0"],
};

function $(sel, root = document) { return root.querySelector(sel); }
function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

function toast(msg, kind = "") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast" + (kind ? " " + kind : "");
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 4000);
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function injectDatalists() {
  if (document.getElementById("dl-codeql-languages")) return;
  const wrap = document.createElement("div");
  wrap.style.display = "none";
  const dl = (id, opts) =>
    `<datalist id="${id}">${opts.map((o) => `<option value="${escapeHtml(o)}"></option>`).join("")}</datalist>`;
  wrap.innerHTML = [
    dl("dl-codeql-languages", CODEQL_LANGUAGES),
    dl("dl-codeql-suites", CODEQL_QUERY_SUITES),
    dl("dl-codeql-packs", CODEQL_OFFICIAL_PACKS),
    dl("dl-codeql-filter-keys", CODEQL_FILTER_KEYS),
  ].join("");
  document.body.appendChild(wrap);
}

function addListRow(kind, initial = {}) {
  const list = $(`#${kind}-list`);
  const row = document.createElement("div");
  row.className = "row";
  if (kind === "queries") {
    row.innerHTML = `
      <input type="text" list="dl-codeql-suites"
        placeholder="security-extended | ./path | owner/repo/path@ref" data-field="uses" />
      <input type="text" placeholder="name (optional)" data-field="name" style="max-width:180px" />
      <button type="button" class="danger" data-remove>×</button>`;
  } else if (kind === "packs") {
    row.innerHTML = `
      <select data-field="language" style="max-width:200px">
        <option value="">(any language)</option>
        ${CODEQL_LANGUAGES.map((l) => `<option value="${l}">${l}</option>`).join("")}
      </select>
      <input type="text" list="dl-codeql-packs"
        placeholder="codeql/javascript-queries@~1.0.0" data-field="pack" />
      <button type="button" class="danger" data-remove>×</button>`;
  } else if (kind === "query-filters") {
    row.innerHTML = `
      <select data-field="kind" style="max-width:110px">
        <option value="include">include</option>
        <option value="exclude">exclude</option>
      </select>
      <input type="text" list="dl-codeql-filter-keys"
        placeholder="key (id, tags, …)" data-field="key" style="max-width:170px" />
      <input type="text" placeholder="value (e.g. security, error, js/sql-injection)" data-field="value" />
      <button type="button" class="danger" data-remove>×</button>`;
    queueMicrotask(() => {
      const keyInput = row.querySelector('[data-field="key"]');
      const valInput = row.querySelector('[data-field="value"]');
      const dlId = `dl-fv-${Math.random().toString(36).slice(2)}`;
      const dl = document.createElement("datalist");
      dl.id = dlId;
      row.appendChild(dl);
      valInput.setAttribute("list", dlId);
      const refresh = () => {
        const opts = CODEQL_FILTER_VALUES_BY_KEY[keyInput.value.trim()] || [];
        dl.innerHTML = opts.map((o) => `<option value="${escapeHtml(o)}"></option>`).join("");
      };
      keyInput.addEventListener("input", refresh);
      keyInput.addEventListener("change", refresh);
      refresh();
    });
  } else {
    row.innerHTML = `
      <input type="text" placeholder="${kind === "paths" ? "src/" : "node_modules/"}" data-field="value" />
      <button type="button" class="danger" data-remove>×</button>`;
  }
  row.querySelector("[data-remove]").addEventListener("click", () => row.remove());
  // Apply initial values
  for (const [field, val] of Object.entries(initial)) {
    const el = row.querySelector(`[data-field="${field}"]`);
    if (el != null) el.value = val ?? "";
  }
  list.appendChild(row);
  return row;
}

function bindForm() {
  injectDatalists();
  $$("[data-add]").forEach((btn) => btn.addEventListener("click", () => addListRow(btn.dataset.add)));
  $("#codeql-preview").addEventListener("click", () => {
    $("#codeql-yaml").textContent = buildYaml();
  });
  $("#codeql-download").addEventListener("click", () => {
    const yaml = buildYaml();
    const blob = new Blob([yaml], { type: "text/yaml" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "codeql-config.yml";
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $("#codeql-load").addEventListener("click", loadExisting);
  $("#codeql-commit").addEventListener("click", commitConfig);
}

function readListRows(kind) {
  return $$(`#${kind}-list .row`).map((row) => {
    const fields = {};
    $$("[data-field]", row).forEach((el) => { fields[el.dataset.field] = el.value.trim(); });
    return fields;
  });
}

function yamlString(s) {
  if (s === "" || s == null) return '""';
  if (/^[A-Za-z0-9_\-./@:~^*+]+$/.test(s) &&
      !/^(true|false|null|yes|no|on|off|~)$/i.test(s) &&
      !/^[-+]?\d+(\.\d+)?$/.test(s)) {
    return s;
  }
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildYaml() {
  const form = $("#codeql-form");
  const name = form.name.value.trim();
  const disableDefault = form.disable_default_queries.checked;
  const threatModel = form.threat_model.value.trim();

  const queries = readListRows("queries").filter((q) => q.uses);
  const packsRows = readListRows("packs").filter((p) => p.pack);
  const paths = readListRows("paths").map((r) => r.value).filter(Boolean);
  const pathsIgnore = readListRows("paths-ignore").map((r) => r.value).filter(Boolean);
  const filters = readListRows("query-filters").filter((f) => f.key && f.value);

  const lines = [];
  if (name) lines.push(`name: ${yamlString(name)}`);
  if (disableDefault) lines.push("disable-default-queries: true");
  if (threatModel) lines.push(`threat-models: ${yamlString(threatModel)}`);

  if (queries.length) {
    lines.push("queries:");
    for (const q of queries) {
      lines.push(`  - uses: ${yamlString(q.uses)}`);
      if (q.name) lines.push(`    name: ${yamlString(q.name)}`);
    }
  }

  if (packsRows.length) {
    const byLang = new Map();
    for (const p of packsRows) {
      const lang = p.language || "";
      if (!byLang.has(lang)) byLang.set(lang, []);
      byLang.get(lang).push(p.pack);
    }
    const noLang = byLang.get("") || [];
    const langKeys = [...byLang.keys()].filter((k) => k !== "");
    lines.push("packs:");
    if (langKeys.length === 0) {
      for (const p of noLang) lines.push(`  - ${yamlString(p)}`);
    } else {
      if (noLang.length) {
        lines.push("  # NOTE: unscoped packs cannot be mixed with language-scoped packs; the following were skipped.");
        for (const p of noLang) lines.push(`  # - ${yamlString(p)}`);
      }
      for (const lang of langKeys) {
        lines.push(`  ${lang}:`);
        for (const p of byLang.get(lang)) lines.push(`    - ${yamlString(p)}`);
      }
    }
  }

  if (paths.length) {
    lines.push("paths:");
    for (const p of paths) lines.push(`  - ${yamlString(p)}`);
  }
  if (pathsIgnore.length) {
    lines.push("paths-ignore:");
    for (const p of pathsIgnore) lines.push(`  - ${yamlString(p)}`);
  }
  if (filters.length) {
    lines.push("query-filters:");
    for (const f of filters) {
      lines.push(`  - ${f.kind}:`);
      lines.push(`      ${f.key}: ${yamlString(f.value)}`);
    }
  }

  if (lines.length === 0) return "# Empty configuration. Fill in fields above and click Preview.";
  return lines.join("\n") + "\n";
}

function getCommitTarget() {
  const form = $("#codeql-form");
  const target = form.repo_target.value.trim();
  if (!target || !target.includes("/")) return null;
  const [owner, repo] = target.split("/", 2);
  return {
    owner, repo,
    branch: form.branch.value.trim() || undefined,
    path: form.path.value.trim() || ".github/codeql/codeql-config.yml",
  };
}

async function loadExisting() {
  const t = getCommitTarget();
  if (!t) { toast("Enter target repo as owner/repo", "error"); return; }
  try {
    const res = await api(`/api/load-config?owner=${encodeURIComponent(t.owner)}&repo=${encodeURIComponent(t.repo)}${t.branch ? `&branch=${encodeURIComponent(t.branch)}` : ""}&path=${encodeURIComponent(t.path)}`);
    if (!res.exists) {
      toast(`No config at ${res.path}`, "");
      return;
    }
    $("#codeql-yaml").textContent = res.yamlContent;
    toast(`Loaded ${res.path}`, "success");
  } catch (err) {
    toast(`Load failed: ${err.message}`, "error");
  }
}

async function commitConfig() {
  const t = getCommitTarget();
  if (!t) { toast("Enter target repo as owner/repo", "error"); return; }
  const yamlContent = buildYaml();
  if (!yamlContent || yamlContent.startsWith("# Empty")) { toast("Configuration is empty", "error"); return; }
  if (!confirm(`Commit ${t.path} to ${t.owner}/${t.repo}${t.branch ? ` on ${t.branch}` : ""}?`)) return;

  try {
    const res = await api("/api/commit-config", {
      method: "POST",
      body: JSON.stringify({
        owner: t.owner, repo: t.repo, branch: t.branch, path: t.path,
        yamlContent, message: `chore: configure CodeQL (${t.path})`,
      }),
    });
    toast(`Committed ${res.path}`, "success");
    if (res.html_url) {
      const note = document.createElement("p");
      note.innerHTML = `Committed: <a href="${res.html_url}" target="_blank" rel="noopener">${escapeHtml(res.path)}</a>`;
      $(".card").appendChild(note);
    }
  } catch (err) {
    toast(`Commit failed: ${err.message}`, "error");
  }
}

async function whoami() {
  try {
    const me = await api("/api/whoami");
    $("#whoami").textContent = me.login ? `Signed in as ${me.login}` : "gh not signed in";
  } catch {
    $("#whoami").textContent = "gh not signed in";
  }
}

function init() {
  bindForm();
  const u = new URL(location.href);
  const owner = u.searchParams.get("owner");
  const repo = u.searchParams.get("repo");
  if (owner && repo) $("#codeql-repo-target").value = `${owner}/${repo}`;
  const branch = u.searchParams.get("branch");
  if (branch) $("[name=branch]").value = branch;
  const path = u.searchParams.get("path");
  if (path) $("[name=path]").value = path;
  whoami();
}

init();
