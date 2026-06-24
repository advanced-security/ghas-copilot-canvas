"use strict";

const state = {
  source: "remote",
  level: "org",
  configs: [],
  deployed: null, // { byName: Map, notAvailable, error }
  selected: new Set(),
  expandedGroups: new Set(),
  expandedPats: new Set(),
  orgs: [],
};

const $ = (id) => document.getElementById(id);

function keyOf(file, name) { return file + "::" + name; }
function norm(s) { return String(s || "").trim().toLowerCase(); }

async function api(path, opts) {
  const res = await fetch(path, opts);
  return res.json();
}

function toast(msg, kind) {
  const t = $("toast");
  t.textContent = msg || "";
  t.className = "toast" + (kind ? " " + kind : "");
}

// ---------- target ----------
function currentTarget() {
  if (state.level === "enterprise") return { enterprise: $("entSlug").value.trim() };
  if (state.level === "org") return { org: pickerValue(ORG) };
  if (state.level === "repo") return { owner: pickerValue(ORGR), repo: pickerValue(REPO) };
  return {};
}
function targetLabel() {
  const t = currentTarget();
  if (state.level === "enterprise") return t.enterprise ? "enterprise/" + t.enterprise : "(no enterprise)";
  if (state.level === "org") return t.org ? "org/" + t.org : "(no org)";
  if (state.level === "repo") return t.owner && t.repo ? t.owner + "/" + t.repo : "(no repo)";
  return "";
}
function updateTargetSummary() {
  $("tgtSummary").textContent = "Target: " + targetLabel();
}

// ---------- orgs / repos ----------
// Each picker renders one of two ways depending on list size:
//   • dropdown mode  — a native <select> with the full list (used when we know
//     the complete list and it is under 100 entries).
//   • search mode    — a type-ahead text input backed by a <datalist> (used for
//     100+ entries). Orgs filter client-side (we already hold the full list);
//     repos query the Search API server-side as the user types.
const ORG = { selId: "orgSel", inpId: "orgSelI", listId: "orgList", mode: "select" };
const ORGR = { selId: "orgSelRepo", inpId: "orgSelRepoI", listId: "orgListR", mode: "select" };
const REPO = { selId: "repoSel", inpId: "repoSelI", listId: "repoList", mode: "select" };

function pickerMode(p, mode) {
  p.mode = mode;
  $(p.selId).classList.toggle("hidden", mode === "search");
  $(p.inpId).classList.toggle("hidden", mode !== "search");
}
function pickerValue(p) {
  return p.mode === "search" ? $(p.inpId).value.trim() : $(p.selId).value;
}
function fillSelect(selId, items, placeholder) {
  const sel = $(selId);
  const cur = sel.value;
  sel.innerHTML = "";
  const ph = document.createElement("option");
  ph.value = ""; ph.textContent = placeholder; sel.appendChild(ph);
  for (const it of items) {
    const o = document.createElement("option");
    o.value = it; o.textContent = it; sel.appendChild(o);
  }
  if (cur && items.includes(cur)) sel.value = cur;
}
function fillDatalist(listId, items) {
  const dl = $(listId);
  dl.innerHTML = "";
  for (const it of items) {
    const o = document.createElement("option");
    o.value = it; dl.appendChild(o);
  }
}

async function loadOrgs() {
  const r = await api("/api/orgs");
  const opts = r.ok ? r.orgs : [];
  state.orgs = opts;
  // 100+ orgs: type-ahead (client-side filter over the full list we hold).
  const search = opts.length >= 100;
  const ph = opts.length ? "Select an org…" : (r.ok ? "No orgs found" : "Error loading orgs");
  for (const p of [ORG, ORGR]) {
    fillSelect(p.selId, opts, ph);
    fillDatalist(p.listId, opts);
    if (search) $(p.inpId).placeholder = "Type to search " + opts.length + " orgs…";
    pickerMode(p, search ? "search" : "select");
  }
  if (!r.ok) toast(r.error || "Failed to load orgs", "err");
  updateTargetSummary();
}

async function loadRepos(org) {
  $(REPO.inpId).value = "";
  fillDatalist(REPO.listId, []);
  if (!org) {
    fillSelect(REPO.selId, [], "Select an org first");
    $(REPO.inpId).placeholder = "Select an org first";
    pickerMode(REPO, "select");
    return;
  }
  fillSelect(REPO.selId, [], "Loading…");
  pickerMode(REPO, "select");
  const r = await api("/api/repos?org=" + encodeURIComponent(org));
  if (!r.ok) {
    fillSelect(REPO.selId, [], "Error loading repos");
    toast(r.error || "Failed to load repos", "err");
    return;
  }
  const names = r.repos.map((x) => x.name);
  if (r.complete) {
    // Full list known (<100 repos): native dropdown, no search needed.
    fillSelect(REPO.selId, names, names.length ? "Select a repo…" : "No repos found");
    pickerMode(REPO, "select");
  } else {
    // 100+ repos: type-ahead, seeded with the first page; live results come from
    // the Search API server-side as the user types (see searchRepos).
    fillDatalist(REPO.listId, names);
    $(REPO.inpId).placeholder = "Type to search repos…";
    pickerMode(REPO, "search");
  }
}

let repoSearchTimer = null;
let repoSearchSeq = 0;
async function searchRepos(org, q) {
  const seq = ++repoSearchSeq;
  const r = await api("/api/repos?org=" + encodeURIComponent(org) + "&q=" + encodeURIComponent(q));
  if (seq !== repoSearchSeq) return; // a newer keystroke superseded this one
  if (r.ok) fillDatalist(REPO.listId, r.repos.map((x) => x.name));
}

// ---------- load patterns ----------
async function loadPatterns() {
  toast("Loading patterns…");
  $("loadBtn").disabled = true;
  let body;
  if (state.source === "local") body = { source: "local", localPath: $("localPath").value.trim() };
  else body = { source: "remote", repo: $("repo").value.trim(), ref: $("ref").value.trim() };
  const r = await api("/api/load-patterns", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  $("loadBtn").disabled = false;
  if (!r.ok) { toast(r.error || "Failed to load", "err"); return; }
  state.configs = r.configs || [];
  state.selected.clear();
  state.deployed = null;
  // expand groups by default
  state.expandedGroups = new Set(state.configs.map((c) => c.file));
  state.expandedPats.clear();
  let total = 0; state.configs.forEach((c) => total += (c.patterns || []).length);
  const src = r.source || {};
  $("srcSummary").textContent = (src.type === "local" ? src.path : (src.repo + "@" + src.ref)) + " — " + state.configs.length + " files, " + total + " patterns";
  toast("Loaded " + total + " patterns from " + state.configs.length + " files", "ok");
  renderTree();
}

// ---------- load deployed state ----------
async function loadState() {
  const target = currentTarget();
  const lbl = targetLabel();
  if (lbl.startsWith("(no")) { toast("Pick a deploy target first", "err"); return; }
  // Deployed state is overlaid onto the loaded pattern tree, so there's nothing
  // to show if patterns haven't been loaded yet. Auto-load them first.
  if (!state.configs.length) {
    await loadPatterns();
    if (!state.configs.length) return; // load failed; loadPatterns already toasted
  }
  toast("Querying deployed patterns for " + lbl + "…");
  $("loadStateBtn").disabled = true;
  const r = await api("/api/list-deployed", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ level: state.level, target }) });
  $("loadStateBtn").disabled = false;
  if (!r.ok) {
    state.deployed = { byName: new Map(), notAvailable: r.notAvailable, error: r.error };
    renderTree();
    toast((r.notAvailable ? "Custom patterns not available for " + lbl + " (404). " : "") + (r.error || ""), "err");
    return;
  }
  const byName = new Map();
  for (const p of r.patterns) byName.set(norm(p.name), p);
  state.deployed = { byName };
  renderTree();
  toast(r.patterns.length + " patterns currently deployed at " + lbl, "ok");
}

// ---------- deploy ----------
function selectedPatterns() {
  const out = [];
  for (const c of state.configs) {
    for (const p of (c.patterns || [])) {
      if (state.selected.has(keyOf(c.file, p.name))) out.push({ config: c, pattern: p });
    }
  }
  return out;
}

function openDeployModal() {
  const target = currentTarget();
  const lbl = targetLabel();
  if (lbl.startsWith("(no")) { toast("Pick a deploy target first", "err"); return; }
  let chosen = selectedPatterns();
  if (chosen.length === 0) { toast("Select at least one pattern", "err"); return; }
  const skip = $("skipDeployed").checked && state.deployed && state.deployed.byName;
  let skipped = 0;
  if (skip) {
    chosen = chosen.filter((x) => { const has = state.deployed.byName.has(norm(x.pattern.name)); if (has) skipped++; return !has; });
  }
  if (chosen.length === 0) { toast("All selected patterns are already deployed (skipped)", "err"); return; }

  const vis = visibleKeySet();
  const hiddenSel = chosen.filter((x) => !vis.has(keyOf(x.config.file, x.pattern.name))).length;

  const bg = document.createElement("div");
  bg.className = "modal-bg";
  const skipNote = skipped ? ("<div class='muted' style='margin-top:6px;'>" + skipped + " already-deployed pattern(s) will be skipped.</div>") : "";
  const hiddenNote = hiddenSel ? ("<div class='muted' style='margin-top:6px;'>⚠ " + hiddenSel + " of these are currently hidden by your filter but will still be deployed.</div>") : "";
  bg.innerHTML =
    "<div class='modal'>" +
    "<h3>Deploy " + chosen.length + " pattern(s) to " + esc(lbl) + "</h3>" +
    "<div class='limit' style='border-radius:6px;'>These patterns will be created as <strong>UNPUBLISHED</strong>. " +
    "Publishing and enabling push protection must be done in the GitHub UI. The API cannot update or delete patterns.</div>" +
    skipNote + hiddenNote +
    "<div class='actions'>" +
    "<button class='btn' id='mCancel'>Cancel</button>" +
    "<button class='btn primary' id='mGo'>Deploy as unpublished</button>" +
    "</div></div>";
  document.body.appendChild(bg);
  $("mCancel").onclick = () => bg.remove();
  $("mGo").onclick = async () => {
    bg.remove();
    await doDeploy(chosen.map((x) => x.pattern.deploy), target);
  };
}

async function doDeploy(patterns, target) {
  toast("Deploying " + patterns.length + " pattern(s)…");
  $("deployBtn").disabled = true;
  const r = await api("/api/deploy", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ level: state.level, target, patterns }) });
  $("deployBtn").disabled = false;
  if (!r.ok) {
    let msg = r.error || "Deploy failed";
    if (r.validationErrors) {
      const parts = [];
      for (const k of Object.keys(r.validationErrors)) {
        const errs = (r.validationErrors[k].errors || []).map((e) => e.message).join("; ");
        parts.push("#" + k + ": " + errs);
      }
      msg += " — " + parts.join(" | ");
    }
    toast(msg, "err");
    return;
  }
  toast("Created " + (r.created || []).length + " pattern(s) as unpublished. Reloading deployed state…", "ok");
  await loadState();
}

// ---------- filters ----------
function patternVisible(p) {
  const q = norm($("search").value);
  if (q && !norm(p.name).includes(q)) return false;
  const dep = state.deployed && state.deployed.byName ? state.deployed.byName.get(norm(p.name)) : null;
  const fState = $("fState").value;
  if (fState === "not_deployed") {
    if (dep) return false;
  } else if (fState !== "all") {
    if (!dep) return false;
    if (dep.state !== fState) return false;
  }
  const fPP = $("fPP").value;
  if (fPP !== "all") {
    if (!dep) return false;
    const on = !!dep.push_protection_enabled;
    if (fPP === "enabled" && !on) return false;
    if (fPP === "disabled" && on) return false;
  }
  return true;
}

// Keys for every pattern that passes the current filter (regardless of group
// expansion). Used for filter-scoped Select all / Deselect all and for warning
// about selections hidden by the filter.
function visibleKeySet() {
  const s = new Set();
  for (const c of state.configs) {
    if (c.error) continue;
    for (const p of (c.patterns || [])) if (patternVisible(p)) s.add(keyOf(c.file, p.name));
  }
  return s;
}

// ---------- render ----------
function esc(s) { const d = document.createElement("div"); d.textContent = String(s == null ? "" : s); return d.innerHTML; }

function badge(cls, text) {
  const b = document.createElement("span");
  b.className = "badge " + cls; b.textContent = text; return b;
}

// Deep link for the push-protection badge. Org + enterprise point at the
// pattern_configurations page (filtered to this pattern by name) where PP is
// toggled. Repo level has no pattern_configurations page, so it uses the same
// per-pattern link as the "open" badge.
function ppConfigUrl(dep) {
  const t = currentTarget();
  if (state.level === "repo") return dep.html_url || null;
  const q = encodeURIComponent('name:"' + (dep.name || "") + '"').replace(/%20/g, "+");
  if (state.level === "org" && t.org) {
    return "https://github.com/organizations/" + encodeURIComponent(t.org) +
      "/settings/security_analysis/pattern_configurations?tab=custom&page=0&query=" + q;
  }
  if (state.level === "enterprise" && t.enterprise) {
    // Enterprise omits tab=custom up front and orders query, page, then tab.
    return "https://github.com/enterprises/" + encodeURIComponent(t.enterprise) +
      "/settings/security_analysis/pattern_configurations?query=" + q + "&page=0&tab=custom";
  }
  return null;
}

function deployedBadges(row, dep) {
  if (!state.deployed) return;
  if (state.deployed.notAvailable) { row.appendChild(badge("b-none", "n/a")); return; }
  if (!dep) { row.appendChild(badge("b-none", "not deployed")); return; }
  row.appendChild(badge(dep.state === "published" ? "b-pub" : "b-unpub", dep.state || "unknown"));
  const ppOn = dep.push_protection_enabled;
  const ppText = "PP " + (ppOn ? "on" : "off");
  // Push protection is UI-only to toggle. When the pattern is published we link
  // the badge to where it can be changed (org/enterprise: pattern_configurations
  // page; repo: the pattern's own page). Unpublished patterns aren't linkable.
  const published = dep.state === "published";
  const ppUrl = published ? ppConfigUrl(dep) : null;
  if (ppUrl) {
    const a = document.createElement("a");
    a.href = ppUrl; a.target = "_blank"; a.rel = "noopener";
    a.className = "badge " + (ppOn ? "b-pp-on" : "b-pp-off-link") + " badge-link";
    a.textContent = ppText + " ↗";
    a.title = (ppOn ? "Push protection enabled" : "Push protection disabled") +
      " — open to change (UI-only)";
    row.appendChild(a);
  } else {
    const b = badge(ppOn ? "b-pp-on" : "b-pp-off", ppText);
    if (!published) {
      b.title = "Push protection is " + (ppOn ? "enabled" : "disabled") +
        ". This pattern is unpublished — publish it in the GitHub UI before it can be linked/managed.";
    }
    row.appendChild(b);
  }
  if (dep.html_url) {
    const a = document.createElement("a");
    a.href = dep.html_url; a.target = "_blank"; a.rel = "noopener";
    a.className = "badge b-none"; a.textContent = "open ↗"; a.title = "Open pattern #" + dep.id + " in GitHub";
    row.appendChild(a);
  }
}

function renderTests(d, tests) {
  if (!tests || !tests.length) return;
  const l = document.createElement("div");
  l.className = "lbl";
  l.textContent = tests.length > 1 ? "Test data (" + tests.length + ")" : "Test data";
  d.appendChild(l);
  for (const tc of tests) {
    const box = document.createElement("pre");
    box.className = "test-box";
    const data = tc.data || "";
    let s = tc.start;
    if (s == null || !Number.isFinite(s)) {
      // No offset: show the box with no highlight.
      box.textContent = data;
    } else {
      let e = tc.end;
      // A missing or negative end offset means "to the end of the data".
      if (e == null || !Number.isFinite(e) || e < 0) e = data.length;
      s = Math.max(0, Math.min(s, data.length));
      e = Math.max(s, Math.min(e, data.length));
      const before = data.slice(0, s);
      const mid = data.slice(s, e);
      const after = data.slice(e);
      if (before) box.appendChild(document.createTextNode(before));
      if (mid) {
        const mark = document.createElement("span");
        mark.className = "mark";
        mark.textContent = mid;
        mark.title = "Matched secret (offset " + s + "–" + e + ")";
        box.appendChild(mark);
      }
      if (after) box.appendChild(document.createTextNode(after));
    }
    d.appendChild(box);
  }
}

function renderDetail(p, dep) {
  const d = document.createElement("div");
  d.className = "detail";
  const add = (label, value, pre) => {
    if (value == null || value === "" || (Array.isArray(value) && value.length === 0)) return;
    const l = document.createElement("div"); l.className = "lbl"; l.textContent = label; d.appendChild(l);
    if (pre) {
      const arr = Array.isArray(value) ? value : [value];
      for (const v of arr) { const pc = document.createElement("pre"); pc.textContent = v; d.appendChild(pc); }
    } else {
      const s = document.createElement("div"); s.textContent = Array.isArray(value) ? value.join(", ") : value; d.appendChild(s);
    }
  };
  if (p.type) add("Type", p.type);
  if (p.version) add("Regex version", p.version);
  if (p.comments && p.comments.length) add("Comments", p.comments.map((c) => "• " + c).join("\n"), true);
  add("Pattern", p.deploy.pattern, true);
  add("Start delimiter", p.deploy.start_delimiter, true);
  add("End delimiter", p.deploy.end_delimiter, true);
  add("Additional must match", p.deploy.must_match, true);
  add("Additional must NOT match", p.deploy.must_not_match, true);
  renderTests(d, p.tests);
  if (dep && dep.html_url) {
    const l = document.createElement("div"); l.className = "lbl"; l.textContent = "Deployed"; d.appendChild(l);
    const a = document.createElement("a"); a.href = dep.html_url; a.target = "_blank"; a.rel = "noopener";
    a.textContent = "#" + dep.id + " — " + (dep.state || "") + " — manage in GitHub UI ↗"; d.appendChild(a);
  }
  return d;
}

function renderTree() {
  const root = $("tree");
  root.innerHTML = "";
  if (!state.configs.length) {
    root.innerHTML = "<div class='muted' style='padding:16px;'>Load a pattern source to begin.</div>";
    $("treeSummary").textContent = "";
    updateSelSummary();
    return;
  }
  let shownPats = 0, totalDeployed = 0, totalPats = 0;

  for (const c of state.configs) {
    const pats = (c.patterns || []);
    totalPats += pats.length;
    const visible = pats.filter(patternVisible).sort((a, b) => {
      // Group sub-rows by type (untyped last), then by name.
      const ta = (a.type || "").toLowerCase(), tb = (b.type || "").toLowerCase();
      if (ta !== tb) {
        if (!ta) return 1;
        if (!tb) return -1;
        return ta.localeCompare(tb);
      }
      return (a.name || "").localeCompare(b.name || "");
    });
    if (c.error) {
      const grp = document.createElement("div"); grp.className = "grp";
      const hd = document.createElement("div"); hd.className = "grp-hd";
      hd.innerHTML = "<span class='caret empty'></span><span class='nm'>" + esc(c.name) + "</span><span class='muted'>" + esc(c.file) + "</span>";
      const err = badge("b-unpub", "error"); err.title = c.error; hd.appendChild(err);
      grp.appendChild(hd); root.appendChild(grp); continue;
    }
    if (!visible.length) continue;

    const grp = document.createElement("div"); grp.className = "grp";
    const hd = document.createElement("div"); hd.className = "grp-hd";

    const caret = document.createElement("span"); caret.className = "caret";
    const expanded = state.expandedGroups.has(c.file);
    caret.textContent = expanded ? "▾" : "▸";
    caret.onclick = () => { if (expanded) state.expandedGroups.delete(c.file); else state.expandedGroups.add(c.file); renderTree(); };
    hd.appendChild(caret);

    const cb = document.createElement("input"); cb.type = "checkbox";
    const selCount = visible.filter((p) => state.selected.has(keyOf(c.file, p.name))).length;
    cb.checked = selCount === visible.length && visible.length > 0;
    cb.indeterminate = selCount > 0 && selCount < visible.length;
    cb.onchange = () => {
      for (const p of visible) { if (cb.checked) state.selected.add(keyOf(c.file, p.name)); else state.selected.delete(keyOf(c.file, p.name)); }
      renderTree();
    };
    hd.appendChild(cb);

    const nm = document.createElement("span"); nm.className = "nm"; nm.textContent = c.name; hd.appendChild(nm);
    const file = document.createElement("span"); file.className = "muted"; file.style.fontSize = "12px"; file.textContent = c.file; hd.appendChild(file);
    hd.appendChild(Object.assign(document.createElement("span"), { className: "spacer" }));

    let depCount = 0;
    if (state.deployed && state.deployed.byName) depCount = visible.filter((p) => state.deployed.byName.has(norm(p.name))).length;
    totalDeployed += depCount;
    const cnt = document.createElement("span"); cnt.className = "muted"; cnt.style.fontSize = "12px";
    cnt.textContent = visible.length + " pattern" + (visible.length === 1 ? "" : "s") + (state.deployed ? " · " + depCount + " deployed" : "");
    hd.appendChild(cnt);

    grp.appendChild(hd);

    if (expanded) {
      for (const p of visible) {
        shownPats++;
        const dep = state.deployed && state.deployed.byName ? state.deployed.byName.get(norm(p.name)) : null;
        const row = document.createElement("div"); row.className = "pat";
        const ph = document.createElement("div"); ph.className = "pat-hd";

        const pc = document.createElement("span"); pc.className = "caret";
        const pexp = state.expandedPats.has(keyOf(c.file, p.name));
        pc.textContent = pexp ? "▾" : "▸";
        pc.onclick = () => { const k = keyOf(c.file, p.name); if (pexp) state.expandedPats.delete(k); else state.expandedPats.add(k); renderTree(); };
        ph.appendChild(pc);

        const pcb = document.createElement("input"); pcb.type = "checkbox";
        pcb.checked = state.selected.has(keyOf(c.file, p.name));
        pcb.onchange = () => { const k = keyOf(c.file, p.name); if (pcb.checked) state.selected.add(k); else state.selected.delete(k); updateSelSummary(); /* update group checkbox */ renderTree(); };
        ph.appendChild(pcb);

        const nmp = document.createElement("span"); nmp.className = "nm"; nmp.textContent = p.name; ph.appendChild(nmp);
        if (p.type) ph.appendChild(badge("b-type", p.type));
        if (p.experimental) ph.appendChild(badge("b-exp", "experimental"));
        ph.appendChild(Object.assign(document.createElement("span"), { className: "spacer" }));
        deployedBadges(ph, dep);

        row.appendChild(ph);
        if (pexp) row.appendChild(renderDetail(p, dep));
        grp.appendChild(row);
      }
    }
    root.appendChild(grp);
  }

  let summary = shownPats + " shown / " + totalPats + " total";
  if (state.deployed) {
    if (state.deployed.notAvailable) summary += " · deployed: not available (404)";
    else summary += " · " + totalDeployed + " deployed in view";
  }
  $("treeSummary").textContent = summary;
  updateSelSummary();
}

function updateSelSummary() {
  const vis = visibleKeySet();
  let hidden = 0;
  for (const k of state.selected) if (!vis.has(k)) hidden++;
  $("selSummary").textContent = state.selected.size + " selected" + (hidden ? " · " + hidden + " hidden by filter" : "");
}

// ---------- wiring ----------
function setSeg(segId, attr, val, cb) {
  for (const b of $(segId).querySelectorAll("button")) {
    b.classList.toggle("active", b.dataset[attr] === val);
  }
  cb(val);
}

function wire() {
  $("toggleLimits").onclick = () => $("limits").classList.toggle("hidden");

  $("srcSeg").onclick = (e) => {
    const b = e.target.closest("button"); if (!b) return;
    setSeg("srcSeg", "src", b.dataset.src, (v) => {
      state.source = v;
      $("srcRemote").classList.toggle("hidden", v !== "remote");
      $("srcLocal").classList.toggle("hidden", v !== "local");
    });
  };

  $("lvlSeg").onclick = (e) => {
    const b = e.target.closest("button"); if (!b) return;
    setSeg("lvlSeg", "lvl", b.dataset.lvl, (v) => {
      state.level = v;
      $("lvlEnterprise").classList.toggle("hidden", v !== "enterprise");
      $("lvlOrg").classList.toggle("hidden", v !== "org");
      $("lvlRepo").classList.toggle("hidden", v !== "repo");
      state.deployed = null; renderTree(); updateTargetSummary();
    });
  };

  $("loadBtn").onclick = loadPatterns;
  $("loadStateBtn").onclick = loadState;
  $("deployBtn").onclick = openDeployModal;
  $("reloadOrgs").onclick = loadOrgs;
  $("reloadOrgs2").onclick = loadOrgs;

  // Org pickers: a change in either the dropdown or the search input updates the
  // target. For the repo-level org we (re)load repos only once the value is a
  // real org, so partial typing doesn't fire a load per keystroke.
  const onOrgChange = () => {
    const v = pickerValue(ORG);
    updateTargetSummary();
    if (v === "" || state.orgs.includes(v)) { state.deployed = null; renderTree(); }
  };
  $("orgSel").onchange = onOrgChange;
  $("orgSelI").oninput = onOrgChange;

  const onOrgRepoChange = () => {
    const v = pickerValue(ORGR);
    updateTargetSummary();
    if (ORGR.mode === "select" || v === "" || state.orgs.includes(v)) loadRepos(v);
  };
  $("orgSelRepo").onchange = onOrgRepoChange;
  $("orgSelRepoI").oninput = onOrgRepoChange;

  $("entSlug").oninput = updateTargetSummary;

  // Repo picker: dropdown selection vs. type-ahead search input.
  const onRepoPicked = () => { state.deployed = null; renderTree(); updateTargetSummary(); };
  $("repoSel").onchange = onRepoPicked;
  $("repoSelI").oninput = () => {
    state.deployed = null; renderTree(); updateTargetSummary();
    const org = pickerValue(ORGR);
    const q = $("repoSelI").value.trim();
    clearTimeout(repoSearchTimer);
    if (!org || !q) return;
    repoSearchTimer = setTimeout(() => searchRepos(org, q), 250);
  };

  for (const id of ["search", "fState", "fPP"]) {
    $(id).oninput = renderTree; $(id).onchange = renderTree;
  }
  $("expandAll").onclick = () => { state.expandedGroups = new Set(state.configs.map((c) => c.file)); renderTree(); };
  $("collapseAll").onclick = () => { state.expandedGroups.clear(); state.expandedPats.clear(); renderTree(); };
  $("selAll").onclick = () => { for (const k of visibleKeySet()) state.selected.add(k); renderTree(); };
  $("deselAll").onclick = () => { for (const k of visibleKeySet()) state.selected.delete(k); renderTree(); };
}

wire();
loadOrgs();
updateTargetSummary();
