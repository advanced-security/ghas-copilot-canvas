(() => {
  "use strict";

  const state = {
    enterprise: null,
    orgs: [], // {login, name, avatarUrl, htmlUrl, repoCount, status, statusDetail, job}
    selected: new Set(),
    activeJobs: new Map(), // jobId -> { orgs: Set<login>, enable }
    pollTimer: null,
    diagnosticCursor: 0,
    diagnosticEntries: [],
    diagnosticLoading: false,
    diagnosticClearing: false,
    diagnosticGeneration: 0,
    diagnosticPollTimer: null,
    diagnosticRefreshTimer: null,
  };

  const MAX_CLIENT_DIAGNOSTICS = 100;

  const $ = (id) => document.getElementById(id);

  async function api(path, opts) {
    const isDiagnosticRequest = path.startsWith("/api/logs");
    try {
      const res = await fetch(path, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
      return data;
    } finally {
      // Every non-log API call nudges the "API activity" panel to refresh
      // shortly after, so it reflects the request that was just made.
      if (!isDiagnosticRequest) requestDiagnosticRefresh();
    }
  }

  function orgByLogin(login) {
    return state.orgs.find((o) => o.login === login);
  }

  // --- Loading ---------------------------------------------------------------

  async function loadWhoami() {
    try {
      const auth = await api("/api/auth");
      renderAuth(auth);
    } catch { /* ignore */ }
  }

  function renderAuth(auth) {
    const active = auth.active;
    $("whoami-login").textContent = active?.login
      ? `Signed in as @${active.login}`
      : "Not signed in";

    const scopesEl = $("whoami-scopes");
    scopesEl.innerHTML = "";
    (active?.scopes || []).forEach((s) => {
      const chip = document.createElement("span");
      chip.className = "scope-chip";
      chip.textContent = s;
      scopesEl.appendChild(chip);
    });
    if (!active?.scopes?.length) {
      const chip = document.createElement("span");
      chip.className = "scope-chip muted";
      chip.textContent = active?.available === false ? "unavailable" : "no scopes";
      scopesEl.appendChild(chip);
    }

    // Only show the mode picker when there are two distinct identities to
    // choose between (i.e. an env token is actually shadowing the keyring).
    const hasChoice = !!auth.envToken;
    $("whoami-modes").classList.toggle("hidden", !hasChoice);
    if (hasChoice) {
      ["auto", "env", "keyring"].forEach((m) => {
        const btn = $(`mode-${m}-btn`);
        btn.classList.toggle("active", auth.mode === m);
        const identity = m === "env" ? auth.envToken : m === "keyring" ? auth.keyring : null;
        btn.title = identity?.login
          ? `${btn.title.split(" (")[0]} — @${identity.login} (${(identity.scopes || []).join(", ") || "no scopes"})`
          : btn.title;
      });
    }
  }

  async function setAuthMode(mode) {
    try {
      const auth = await api("/api/auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode }) });
      renderAuth(auth);
    } catch (err) {
      $("load-status").textContent = `Auth switch failed: ${err.message}`;
    }
  }

  async function loadOrgs() {
    const enterprise = $("enterprise-input").value.trim();
    if (!enterprise) return;
    const statusEl = $("load-status");
    statusEl.textContent = "Loading organizations…";
    $("load-btn").disabled = true;
    try {
      const data = await api(`/api/orgs?enterprise=${encodeURIComponent(enterprise)}`);
      state.enterprise = data;
      state.orgs = data.orgs.map((o) => ({ ...o, status: "unknown", statusDetail: null }));
      state.selected.clear();
      statusEl.textContent = `${data.orgs.length} organization(s) in ${data.enterprise}${data.truncated ? " (truncated, more available)" : ""}`;
      $("empty-state").classList.add("hidden");
      $("toolbar").classList.remove("hidden");
      $("table-wrap").classList.remove("hidden");
      renderTable();
      checkAllOrgs();
    } catch (err) {
      statusEl.textContent = `Error: ${err.message}`;
    } finally {
      $("load-btn").disabled = false;
    }
  }

  // --- Rendering ---------------------------------------------------------------

  function statusBadge(org) {
    const map = {
      enabled: ["enabled", "✅ Enabled"],
      disabled: ["disabled", "⛔ Disabled"],
      partial: ["partial", "🟡 Partial"],
      "not-eligible": ["not-eligible", "— Not eligible"],
      "policy-blocked": ["policy-blocked", "🔒 Blocked by policy"],
      unknown: ["unknown", "Unknown"],
      checking: ["checking", "Checking…"],
      applying: ["checking", "Applying…"],
    };
    const [cls, label] = map[org.status] || map.unknown;
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function aiStatusBadge(org) {
    if (org.status === "checking" || org.status === "applying" || org.aiApplying) return `<span class="badge checking">…</span>`;
    const overall = org.statusDetail?.aiOverall;
    const map = {
      enabled: ["enabled", "🤖 On"],
      disabled: ["disabled", "🤖 Off"],
      partial: ["partial", "🟡 Partial"],
      "not-eligible": ["not-eligible", "— N/A"],
      "policy-blocked": ["policy-blocked", "🔒 Blocked"],
      error: ["error", "⚠️ Error"],
      unknown: ["unknown", "Unknown"],
    };
    const [cls, label] = map[overall] || map.unknown;
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function renderTable() {
    const tbody = $("orgs-tbody");
    tbody.innerHTML = "";
    for (const org of state.orgs) {
      const tr = document.createElement("tr");
      tr.dataset.login = org.login;

      const checked = state.selected.has(org.login) ? "checked" : "";
      const avatar = org.avatarUrl ? `<img class="org-avatar" src="${org.avatarUrl}" alt="" />` : `<span class="org-avatar"></span>`;
      const repoCount = org.repoCount != null ? org.repoCount.toLocaleString() : "?";

      let detail = "";
      if (org.statusDetail && org.status !== "checking" && org.status !== "applying") {
        const d = org.statusDetail;
        if (d.error) {
          detail = `<div class="status-detail status-error">${escapeHtml(d.error)}</div>`;
        } else if (d.counts) {
          const parts = [];
          if (d.counts.configured) parts.push(`${d.counts.configured} on`);
          if (d.counts["not-configured"]) parts.push(`${d.counts["not-configured"]} off`);
          if (d.counts["not-eligible"]) parts.push(`${d.counts["not-eligible"]} n/a`);
          if (d.counts["policy-blocked"]) parts.push(`${d.counts["policy-blocked"]} 🔒 blocked`);
          if (d.counts.error) parts.push(`${d.counts.error} err`);
          const sampleNote = d.sampled ? ` (sampled ${d.sampledRepos}/${d.totalRepos})` : ` (${d.totalRepos} repos)`;
          const blockedTitle = d.counts["policy-blocked"]
            ? ` title="An org or enterprise policy prevents changing Code Quality on these repos. Check Enterprise settings → Policies → Code quality (Organization access), or this org's own access setting."`
            : "";
          detail = `<div class="status-detail"${blockedTitle}>${parts.join(", ")}${sampleNote}</div>`;
        }
      }

      let progress = "";
      if (org.jobProgress) {
        const p = org.jobProgress;
        const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
        progress = `
          <div class="progress-outer"><div class="progress-inner" style="width:${pct}%"></div></div>
          <div class="progress-label">${p.done}/${p.total} repos · ${p.status}</div>`;
      }

      let aiDetail = "";
      if (org.statusDetail && org.statusDetail.aiCounts && org.status !== "checking" && !org.aiApplying) {
        const ai = org.statusDetail.aiCounts;
        const parts = [];
        if (ai.on) parts.push(`${ai.on} on`);
        if (ai.off) parts.push(`${ai.off} off`);
        if (ai["n/a"]) parts.push(`${ai["n/a"]} n/a`);
        if (ai.blocked) parts.push(`${ai.blocked} 🔒 blocked`);
        if (ai.error) parts.push(`${ai.error} err`);
        aiDetail = parts.length
          ? `<div class="status-detail" title="AI findings (Scans) require Code Quality to be configured on a repo before they can be turned on.">${parts.join(", ")}</div>`
          : "";
      }
      let aiProgress = "";
      if (org.aiJobProgress) {
        const p = org.aiJobProgress;
        const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
        aiProgress = `
          <div class="progress-outer"><div class="progress-inner" style="width:${pct}%"></div></div>
          <div class="progress-label">${p.done}/${p.total} repos · ${p.status}</div>`;
      }

      tr.innerHTML = `
        <td class="col-check"><input type="checkbox" class="row-check" ${checked} /></td>
        <td class="col-org">
          <div class="org-cell">
            ${avatar}
            <div>
              <div class="org-login">${escapeHtml(org.login)}</div>
              ${org.name && org.name !== org.login ? `<div class="org-name">${escapeHtml(org.name)}</div>` : ""}
            </div>
            ${org.login ? `<a class="org-link" href="https://github.com/organizations/${encodeURIComponent(org.login)}/settings/code-quality" target="_blank" rel="noreferrer" title="Open org Code quality settings">↗</a>` : ""}
          </div>
        </td>
        <td class="col-repos">${repoCount}</td>
        <td class="col-status">${statusBadge(org)}${detail}${progress}</td>
        <td class="col-ai">${aiStatusBadge(org)}${aiDetail}${aiProgress}</td>
        <td class="col-actions">
          <div class="row-actions">
            <div class="row-picker">
              <select class="row-access-select" title="Repository access for this org">
                <option value="" selected disabled>Set access…</option>
                <option value="all">All repositories</option>
                <option value="none">No repositories</option>
                <option value="filter">Matching a filter…</option>
                <option value="let-decide" title="Not settable via API — no endpoint exists for this org-level policy.">Let repositories decide (unsupported)</option>
                <option value="selected-repos" title="Per-repo selection is intentionally unsupported here — orgs can have 10k+ repos.">Selected repositories… (unsupported)</option>
              </select>
              <button class="btn small row-access-apply" disabled>Apply</button>
            </div>
            <div class="row-picker">
              <select class="row-ai-select" title="AI scans for this org (only applies to repos where Code Quality is already configured)">
                <option value="" selected disabled>AI scans…</option>
                <option value="on">Enable AI scans</option>
                <option value="off">Disable AI scans</option>
              </select>
              <button class="btn small row-ai-apply" disabled>Apply</button>
            </div>
          </div>
        </td>
      `;

      tr.querySelector(".row-check").addEventListener("change", (e) => {
        if (e.target.checked) state.selected.add(org.login);
        else state.selected.delete(org.login);
        updateSelectionUi();
      });
      const rowAccessSelect = tr.querySelector(".row-access-select");
      const rowAccessApply = tr.querySelector(".row-access-apply");
      rowAccessSelect.addEventListener("change", (e) => { rowAccessApply.disabled = !e.target.value; });
      rowAccessApply.addEventListener("click", () => {
        const value = rowAccessSelect.value;
        rowAccessSelect.value = "";
        rowAccessApply.disabled = true;
        onAccessChoice(value, [org.login], `organization "${org.login}"`);
      });
      const rowAiSelect = tr.querySelector(".row-ai-select");
      const rowAiApply = tr.querySelector(".row-ai-apply");
      rowAiSelect.addEventListener("change", (e) => { rowAiApply.disabled = !e.target.value; });
      rowAiApply.addEventListener("click", () => {
        const value = rowAiSelect.value;
        rowAiSelect.value = "";
        rowAiApply.disabled = true;
        onAiChoice(value, [org.login]);
      });

      tbody.appendChild(tr);
    }
    updateSelectionUi();
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function updateSelectionUi() {
    $("select-count").textContent = `${state.selected.size} selected`;
    const allChecked = state.orgs.length > 0 && state.selected.size === state.orgs.length;
    $("select-all").checked = allChecked;
    const hasSelection = state.selected.size > 0;
    $("check-selected-btn").disabled = !hasSelection;
    $("access-select").disabled = !hasSelection;
    $("ai-select").disabled = !hasSelection;
    if (!hasSelection) {
      $("access-select").value = "";
      $("ai-select").value = "";
      $("access-apply-btn").disabled = true;
      $("ai-apply-btn").disabled = true;
    } else {
      $("access-apply-btn").disabled = !$("access-select").value;
      $("ai-apply-btn").disabled = !$("ai-select").value;
    }
  }

  function updateRow(login) {
    const org = orgByLogin(login);
    if (!org) return;
    const tr = document.querySelector(`tr[data-login="${CSS.escape(login)}"]`);
    if (!tr) return renderTable();
    // Cheap approach: re-render the whole table (small: orgs, not repos).
    renderTable();
  }

  // --- Status check ---------------------------------------------------------

  async function checkOrgStatus(login) {
    const org = orgByLogin(login);
    if (!org) return;
    org.status = "checking";
    updateRow(login);
    try {
      const data = await api(`/api/org-status?org=${encodeURIComponent(login)}`);
      org.status = data.overall;
      org.statusDetail = data;
    } catch (err) {
      org.status = "unknown";
      org.statusDetail = { error: err.message };
    }
    updateRow(login);
  }

  async function checkSelected() {
    const logins = [...state.selected];
    await Promise.all(logins.map((l) => checkOrgStatus(l)));
  }

  // Auto-checks every loaded org's status, a few at a time so we don't fan out
  // dozens of simultaneous requests when an enterprise has many organizations.
  async function checkAllOrgs() {
    const logins = state.orgs.map((o) => o.login);
    const CLIENT_CONCURRENCY = 4;
    let idx = 0;
    async function worker() {
      while (idx < logins.length) {
        const login = logins[idx++];
        await checkOrgStatus(login);
      }
    }
    await Promise.all(Array.from({ length: Math.min(CLIENT_CONCURRENCY, logins.length) }, worker));
  }

  // --- Billing confirmation modal -----------------------------------------------

  let billingConfirmResolve = null;

  function closeBillingConfirm(result) {
    $("billing-confirm-overlay").classList.add("hidden");
    if (billingConfirmResolve) {
      const resolve = billingConfirmResolve;
      billingConfirmResolve = null;
      resolve(result);
    }
  }

  // Shown before any action that enables Code Quality or AI findings, since both
  // incur billing (committer licenses, AI credits, Action minutes). Resolves true
  // if the user confirms, false if they cancel/dismiss.
  function confirmBillingChange(logins) {
    const orgCount = logins.length;
    const repoCount = logins.reduce((sum, login) => {
      const org = orgByLogin(login);
      return sum + (org && org.repoCount != null ? org.repoCount : 0);
    }, 0);
    const repoLabel = repoCount === 1 ? "1 repository" : `${repoCount.toLocaleString()} repositories`;
    const scopeLabel = orgCount === 1 ? "this organization" : `${orgCount} organizations`;
    $("billing-confirm-summary").textContent =
      `Enabling across ${repoLabel} in ${scopeLabel} will incur additional costs based on:`;
    $("billing-confirm-overlay").classList.remove("hidden");
    return new Promise((resolve) => { billingConfirmResolve = resolve; });
  }

  // --- Enable/disable ---------------------------------------------------------

  async function toggleOrgs(logins, enable, filter, target = "quality") {
    if (!logins.length) return;
    if (enable) {
      const confirmed = await confirmBillingChange(logins);
      if (!confirmed) return;
    }
    for (const login of logins) {
      const org = orgByLogin(login);
      if (!org) continue;
      if (target === "ai") {
        org.aiApplying = true;
        org.aiJobProgress = { done: 0, total: 0, status: "queued" };
      } else {
        org.status = "applying";
        org.jobProgress = { done: 0, total: 0, status: "queued" };
      }
    }
    renderTable();
    try {
      const job = await api("/api/bulk-toggle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ orgs: logins, enable, filter: filter || undefined, target }),
      });
      state.activeJobs.set(job.id, { orgs: new Set(logins), enable, target });
      startPolling();
    } catch (err) {
      for (const login of logins) {
        const org = orgByLogin(login);
        if (!org) continue;
        if (target === "ai") {
          org.aiApplying = false;
          org.aiJobProgress = null;
        } else {
          org.status = "unknown";
          org.statusDetail = { error: err.message };
          org.jobProgress = null;
        }
      }
      renderTable();
    }
  }

  // --- Repository access dropdown (toolbar + per-row) --------------------------

  let filterScope = { logins: [], label: "" };

  function onAccessChoice(value, logins, label) {
    if (!value || !logins.length) return;
    if (value === "all") return toggleOrgs(logins, true);
    if (value === "none") return toggleOrgs(logins, false);
    if (value === "filter") return openFilterPanel(logins, label);
    if (value === "let-decide") {
      if (logins.length === 1) {
        window.open(`https://github.com/organizations/${encodeURIComponent(logins[0])}/settings/code-quality`, "_blank", "noreferrer");
      } else {
        alert("\"Let repositories decide\" has no API - open each org's settings page individually (use the ↗ link in its row) to set it there.");
      }
    }
    // "selected-repos" is disabled in the <select> and shouldn't reach here.
  }

  function onAiChoice(value, logins) {
    if (!value || !logins.length) return;
    if (value === "on") return toggleOrgs(logins, true, undefined, "ai");
    if (value === "off") return toggleOrgs(logins, false, undefined, "ai");
  }

  function openFilterPanel(logins, label) {
    filterScope = { logins, label };
    $("filter-panel-target").textContent = `Matching a filter — applies to ${label}`;
    $("filter-panel").classList.remove("hidden");
  }

  function closeFilterPanel() {
    $("filter-panel").classList.add("hidden");
    filterScope = { logins: [], label: "" };
  }

  function currentFilter() {
    const filter = {
      namePattern: $("filter-name").value.trim(),
      language: $("filter-language").value.trim(),
      topic: $("filter-topic").value.trim(),
    };
    return Object.values(filter).some(Boolean) ? filter : null;
  }

  function applyFilter(enable) {
    if (!filterScope.logins.length) return;
    const filter = currentFilter();
    if (!filter) { alert("Enter at least one filter criterion (name, language, or topic)."); return; }
    toggleOrgs(filterScope.logins, enable, filter);
    closeFilterPanel();
  }

  function startPolling() {
    if (state.pollTimer) return;
    state.pollTimer = setInterval(pollJobs, 1200);
    pollJobs();
  }

  async function pollJobs() {
    if (!state.activeJobs.size) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      return;
    }
    for (const [jobId, meta] of [...state.activeJobs.entries()]) {
      try {
        const snap = await api(`/api/job?id=${encodeURIComponent(jobId)}`);
        let allDone = true;
        for (const orgJob of snap.orgs) {
          const org = orgByLogin(orgJob.login);
          if (!org) continue;
          if (meta.target === "ai") {
            org.aiJobProgress = { done: orgJob.done, total: orgJob.total, status: orgJob.status };
            if (orgJob.status === "done") {
              const requiresQuality = orgJob.requiresQuality || 0;
              const policyBlocked = orgJob.policyBlocked || 0;
              const notEligible = orgJob.skipped - policyBlocked - requiresQuality;
              const aiCounts = {
                on: meta.enable ? orgJob.succeeded : 0,
                off: meta.enable ? 0 : orgJob.succeeded,
                "n/a": notEligible + requiresQuality,
                blocked: policyBlocked,
                error: orgJob.failed,
              };
              // Mirror the server's sampleOrgStatus aiOverall derivation so the
              // badge reflects the toggle we just ran instead of a stale
              // pre-toggle sample (aiCounts alone isn't read by aiStatusBadge).
              const aiCheckable = aiCounts.on + aiCounts.off;
              let aiOverall = "unknown";
              if (aiCheckable > 0) {
                if (aiCounts.on === aiCheckable) aiOverall = "enabled";
                else if (aiCounts.off === aiCheckable) aiOverall = "disabled";
                else aiOverall = "partial";
              } else if (aiCounts["n/a"] > 0) {
                aiOverall = "not-eligible";
              } else if (aiCounts.blocked > 0) {
                aiOverall = "policy-blocked";
              } else if (aiCounts.error > 0) {
                aiOverall = "error";
              }
              org.statusDetail = { ...(org.statusDetail || {}), aiCounts, aiOverall };
              org.aiApplying = false;
              org.aiJobProgress = null;
            } else if (orgJob.status === "failed" || orgJob.status === "cancelled") {
              org.aiApplying = false;
              org.aiJobProgress = null;
            } else {
              allDone = false;
            }
            continue;
          }
          org.jobProgress = { done: orgJob.done, total: orgJob.total, status: orgJob.status };
          if (orgJob.status === "done") {
            const notEligible = orgJob.skipped - (orgJob.policyBlocked || 0);
            const allBlocked = orgJob.total > 0 && orgJob.succeeded === 0 && (orgJob.policyBlocked || 0) === orgJob.total;
            org.status = allBlocked ? "policy-blocked" : (meta.enable ? "enabled" : "disabled");
            org.statusDetail = orgJob.failed || orgJob.skipped
              ? { counts: { configured: meta.enable ? orgJob.succeeded : 0, "not-configured": meta.enable ? 0 : orgJob.succeeded, "not-eligible": notEligible, "policy-blocked": orgJob.policyBlocked || 0, error: orgJob.failed }, totalRepos: orgJob.total, sampledRepos: orgJob.total, sampled: false }
              : null;
            org.jobProgress = null;
          } else if (orgJob.status === "failed" || orgJob.status === "cancelled") {
            org.status = "unknown";
            org.statusDetail = { error: orgJob.errors[0] || orgJob.status };
            org.jobProgress = null;
          } else {
            allDone = false;
          }
        }
        if (allDone) state.activeJobs.delete(jobId);
      } catch {
        state.activeJobs.delete(jobId);
      }
    }
    renderTable();
  }

  // --- API activity log tail ---------------------------------------------------

  function diagnosticJson(value) {
    if (typeof value === "string") return value;
    return JSON.stringify(value, null, 2);
  }

  function diagnosticStatus(entry) {
    return entry.response?.status || entry.error?.status || entry.level;
  }

  function diagnosticSection(title, value) {
    if (value === undefined) return "";
    return `<section><h4>${escapeHtml(title)}</h4><pre>${escapeHtml(diagnosticJson(value))}</pre></section>`;
  }

  function renderDiagnostics() {
    const list = $("diagnostic-list");
    const openEntryIds = new Set(
      [...list.querySelectorAll(".diagnostic-entry[open]")].map((entry) => Number(entry.dataset.entryId)),
    );
    const wasNearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 32;
    const count = state.diagnosticEntries.length;
    $("diagnostic-count").textContent = `${count} entr${count === 1 ? "y" : "ies"}`;
    $("diagnostic-count").className = `status-chip ${count ? "success" : "neutral"}`;
    if (!count) {
      list.innerHTML = `<div class="empty-list"><strong>No API activity yet</strong><span>gh CLI calls will appear here as you use the canvas.</span></div>`;
      return;
    }

    list.innerHTML = state.diagnosticEntries.map((entry) => {
      const timestamp = new Date(entry.timestamp);
      const time = Number.isNaN(timestamp.getTime()) ? entry.timestamp : timestamp.toLocaleTimeString();
      const status = diagnosticStatus(entry);
      return `
        <details class="diagnostic-entry ${escapeHtml(entry.level)}" data-entry-id="${escapeHtml(entry.id)}">
          <summary>
            <time datetime="${escapeHtml(entry.timestamp)}">${escapeHtml(time)}</time>
            <span class="diagnostic-source">${escapeHtml(entry.source)}</span>
            <span class="diagnostic-operation">${escapeHtml(entry.operation)}</span>
            <span class="diagnostic-status">${escapeHtml(status)}</span>
            <span class="diagnostic-duration">${entry.durationMs == null ? "" : `${escapeHtml(entry.durationMs)} ms`}</span>
          </summary>
          <div class="diagnostic-content">
            ${entry.message ? `<p>${escapeHtml(entry.message)}</p>` : ""}
            ${diagnosticSection("Request", entry.request)}
            ${diagnosticSection("Response", entry.response)}
            ${diagnosticSection("Error", entry.error)}
          </div>
        </details>`;
    }).join("");
    list.querySelectorAll(".diagnostic-entry").forEach((entry) => {
      entry.open = openEntryIds.has(Number(entry.dataset.entryId));
    });
    if ($("diagnostic-panel").open && wasNearBottom) list.scrollTop = list.scrollHeight;
  }

  async function refreshDiagnostics() {
    if (state.diagnosticLoading || state.diagnosticClearing) return;
    const generation = state.diagnosticGeneration;
    state.diagnosticLoading = true;
    try {
      const result = await api(`/api/logs?after=${state.diagnosticCursor}`);
      if (generation !== state.diagnosticGeneration || state.diagnosticClearing) return;
      const knownIds = new Set(state.diagnosticEntries.map((entry) => entry.id));
      const additions = (result.entries || []).filter((entry) => !knownIds.has(entry.id));
      state.diagnosticEntries = [...state.diagnosticEntries, ...additions].slice(-MAX_CLIENT_DIAGNOSTICS);
      state.diagnosticCursor = result.cursor || state.diagnosticCursor;
      $("diagnostic-hint").textContent = `Held only in memory for this canvas. Credentials are redacted. Retaining ${result.retained || 0} of ${result.maxEntries || MAX_CLIENT_DIAGNOSTICS} entries.`;
      if (additions.length || !state.diagnosticEntries.length) renderDiagnostics();
    } catch (err) {
      $("diagnostic-hint").textContent = `Could not refresh activity: ${err.message}`;
    } finally {
      state.diagnosticLoading = false;
    }
  }

  function requestDiagnosticRefresh() {
    clearTimeout(state.diagnosticRefreshTimer);
    state.diagnosticRefreshTimer = setTimeout(refreshDiagnostics, 100);
  }

  function startDiagnosticPolling() {
    if (state.diagnosticPollTimer) return;
    refreshDiagnostics();
    state.diagnosticPollTimer = setInterval(refreshDiagnostics, 1_500);
  }

  function stopDiagnosticPolling() {
    clearInterval(state.diagnosticPollTimer);
    state.diagnosticPollTimer = null;
  }

  async function copyDiagnosticValue(value, successMessage) {
    const text = `${diagnosticJson(value)}\n`;
    try {
      await navigator.clipboard.writeText(text);
      $("diagnostic-hint").textContent = successMessage;
    } catch {
      $("diagnostic-hint").textContent = "Clipboard access failed. Expand the entry and copy it manually.";
    }
  }

  async function copyLatestResponse() {
    const latest = [...state.diagnosticEntries].reverse()
      .find((entry) => entry.response !== undefined);
    if (!latest) {
      $("diagnostic-hint").textContent = "No API response is available yet.";
      return;
    }
    await copyDiagnosticValue(latest.response.body ?? latest.response, "Latest API response copied.");
  }

  async function copyDiagnostics() {
    await copyDiagnosticValue(state.diagnosticEntries, "API activity copied.");
  }

  async function clearDiagnostics() {
    state.diagnosticGeneration += 1;
    state.diagnosticClearing = true;
    try {
      const result = await api("/api/logs", { method: "DELETE" });
      state.diagnosticEntries = [];
      state.diagnosticCursor = result.cursor || state.diagnosticCursor;
      renderDiagnostics();
      $("diagnostic-hint").textContent = "Activity cleared. New requests will appear here.";
    } catch (err) {
      $("diagnostic-hint").textContent = `Could not clear API activity: ${err.message}`;
    } finally {
      state.diagnosticClearing = false;
    }
  }

  // --- Wiring -----------------------------------------------------------------

  $("load-btn").addEventListener("click", loadOrgs);
  $("enterprise-input").addEventListener("keydown", (e) => { if (e.key === "Enter") loadOrgs(); });

  $("select-all").addEventListener("change", (e) => {
    if (e.target.checked) state.orgs.forEach((o) => state.selected.add(o.login));
    else state.selected.clear();
    renderTable();
  });

  $("check-selected-btn").addEventListener("click", checkSelected);
  $("access-select").addEventListener("change", (e) => {
    $("access-apply-btn").disabled = !e.target.value;
  });
  $("access-apply-btn").addEventListener("click", () => {
    const value = $("access-select").value;
    const logins = [...state.selected];
    $("access-select").value = "";
    $("access-apply-btn").disabled = true;
    onAccessChoice(value, logins, `${logins.length} selected organization(s)`);
  });
  $("ai-select").addEventListener("change", (e) => {
    $("ai-apply-btn").disabled = !e.target.value;
  });
  $("ai-apply-btn").addEventListener("click", () => {
    const value = $("ai-select").value;
    const logins = [...state.selected];
    $("ai-select").value = "";
    $("ai-apply-btn").disabled = true;
    onAiChoice(value, logins);
  });
  $("filter-panel-close").addEventListener("click", closeFilterPanel);
  $("filter-enable-btn").addEventListener("click", () => applyFilter(true));
  $("filter-disable-btn").addEventListener("click", () => applyFilter(false));

  $("billing-confirm-close").addEventListener("click", () => closeBillingConfirm(false));
  $("billing-confirm-cancel").addEventListener("click", () => closeBillingConfirm(false));
  $("billing-confirm-confirm").addEventListener("click", () => closeBillingConfirm(true));
  $("billing-confirm-overlay").addEventListener("click", (e) => {
    if (e.target.id === "billing-confirm-overlay") closeBillingConfirm(false);
  });

  $("mode-auto-btn").addEventListener("click", () => setAuthMode("auto"));
  $("mode-env-btn").addEventListener("click", () => setAuthMode("env"));
  $("mode-keyring-btn").addEventListener("click", () => setAuthMode("keyring"));

  $("diagnostic-panel").addEventListener("toggle", () => {
    if ($("diagnostic-panel").open) startDiagnosticPolling();
    else stopDiagnosticPolling();
  });
  $("diagnostic-refresh-btn").addEventListener("click", refreshDiagnostics);
  $("diagnostic-copy-latest-btn").addEventListener("click", copyLatestResponse);
  $("diagnostic-copy-all-btn").addEventListener("click", copyDiagnostics);
  $("diagnostic-clear-btn").addEventListener("click", clearDiagnostics);

  // Pre-fill enterprise from query string (canvas open input) and auto-load.
  const params = new URLSearchParams(location.search);
  const preEnterprise = params.get("enterprise");
  if (preEnterprise) {
    $("enterprise-input").value = preEnterprise;
    loadOrgs();
  }

  loadWhoami();
})();
