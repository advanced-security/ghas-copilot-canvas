import {
  ECOSYSTEMS,
  createGitHubDocsSampleOsv,
  cvssV3BaseScore,
  cvssV3Vector,
  parseCvssV3Vector,
  severityForScore,
  validateOsv,
} from "/advisory.js";

const fragmentApiToken = new URLSearchParams(location.hash.slice(1)).get("apiToken") || "";
if (fragmentApiToken) {
  sessionStorage.setItem("canvasApiToken", fragmentApiToken);
  history.replaceState(null, "", `${location.pathname}${location.search}`);
}
const API_TOKEN = fragmentApiToken || sessionStorage.getItem("canvasApiToken") || "";

const state = {
  sourceType: "enterprise",
  targetType: "enterprise",
  sourceSlug: "",
  targetSlug: "",
  previewFeaturesEnabled: false,
  advisories: [],
  selectedGhsaId: null,
  selectedPermalink: null,
  selectedSourceScope: null,
  jsonDirty: false,
  deployTokenConfigured: false,
  generatedDeployToken: null,
  authContext: null,
  diagnosticCursor: 0,
  diagnosticEntries: [],
  diagnosticLoading: false,
  diagnosticClearing: false,
  diagnosticGeneration: 0,
  diagnosticPollTimer: null,
  diagnosticRefreshTimer: null,
};

const MAX_CLIENT_DIAGNOSTICS = 100;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function scopePills(values, emptyText = "None reported") {
  if (!values?.length) return `<span class="muted">${escapeHtml(emptyText)}</span>`;
  return `<span class="scope-list">${values.map((value) =>
    `<span class="scope-pill">${escapeHtml(value)}</span>`
  ).join("")}</span>`;
}

function renderAuthContext() {
  const context = state.authContext || {};
  const credential = state.generatedDeployToken;
  const pastedToken = Boolean($("#deployToken")?.value.trim());
  const appSummary = credential
    ? `App: ${credential.scope.type}/${credential.scope.slug}`
    : pastedToken
      ? "App token pasted"
      : state.deployTokenConfigured
        ? "App token configured"
        : "";
  $("#sessionStatus").textContent = context.login
    ? `Signed in as ${context.login}${appSummary ? ` - ${appSummary}` : ""}`
    : (context.error || "gh is not authenticated");

  const userBlocks = (context.credentials || []).map((item) => `
    <div class="auth-block">
      <h3>${escapeHtml(item.label)}</h3>
      <dl>
        <dt>Identity</dt><dd>${escapeHtml(item.login || "Unknown")}</dd>
        <dt>OAuth scopes</dt><dd>${scopePills(item.scopes)}</dd>
      </dl>
    </div>
  `).join("");

  let appBlock = "";
  if (credential) {
    const permissions = Object.entries(credential.permissions || {})
      .map(([name, access]) => `${name}:${access}`);
    appBlock = `
      <div class="auth-block">
        <h3>Generated GitHub App token</h3>
        <dl>
          <dt>App</dt><dd>${escapeHtml(credential.appSlug || "Unknown")}</dd>
          <dt>Installation</dt><dd>${escapeHtml(credential.installationId)}</dd>
          <dt>Target</dt><dd>${escapeHtml(`${credential.scope.type}/${credential.scope.slug}`)}</dd>
          <dt>Permissions</dt><dd>${scopePills(permissions)}</dd>
          <dt>Expires</dt><dd>${escapeHtml(new Date(credential.expiresAt).toLocaleString())}</dd>
        </dl>
      </div>`;
  } else if (pastedToken || state.deployTokenConfigured) {
    appBlock = `
      <div class="auth-block">
        <h3>GitHub App installation token</h3>
        <p>${pastedToken ? "A token is present in the password field." : "GH_INNERSOURCE_TOKEN is configured."} Its permissions are verified by GitHub when deployment is attempted.</p>
      </div>`;
  } else {
    appBlock = `
      <div class="auth-block">
        <h3>GitHub App installation token</h3>
        <p class="muted">No deployment token is currently available.</p>
      </div>`;
  }
  $("#authPopover").innerHTML = userBlocks || `
    <div class="auth-block">
      <h3>User credential</h3>
      <p class="muted">${escapeHtml(context.error || "No authenticated gh credential found.")}</p>
    </div>`;
  $("#authPopover").insertAdjacentHTML("beforeend", appBlock);
}

async function generateDeployToken() {
  const button = $("#generateDeployToken");
  const target = currentTarget();
  const appIdentifier = $("#appIdentifier").value.trim();
  const installationId = $("#installationId").value.trim();
  const fileInput = $("#appPrivateKey");
  const file = fileInput.files?.[0];

  if (!target.slug) {
    toast(`Enter a target ${target.type} slug first.`, "error");
    return;
  }
  if (!appIdentifier) {
    toast("Enter the GitHub App ID or client ID.", "error");
    return;
  }
  if (!file) {
    toast("Select the GitHub App private key PEM file.", "error");
    return;
  }

  let privateKey = "";
  setBusy(button, true, "Generating...");
  try {
    privateKey = await file.text();
    const response = await api("/api/installation-token", {
      method: "POST",
      body: JSON.stringify({
        appIdentifier,
        installationId: installationId || undefined,
        privateKey,
        scope: target,
      }),
    });
    state.generatedDeployToken = response.credential;
    fileInput.value = "";
    $("#privateKeyHint").textContent = `${file.name} was used in memory and released. Select it again to regenerate.`;
    renderCredentialState();
    toast("GitHub App installation token generated.", "success");
  } catch (error) {
    $("#credentialMessage").textContent = error.message;
    $("#credentialMessage").className = "inline-message credential-message error";
    toast(`Token generation failed: ${error.message}`, "error");
  } finally {
    privateKey = "";
    setBusy(button, false);
  }
}

async function clearGeneratedToken() {
  const button = $("#clearGeneratedToken");
  setBusy(button, true, "Clearing...");
  try {
    await api("/api/installation-token", { method: "DELETE" });
    state.generatedDeployToken = null;
    renderCredentialState();
    toast("Generated installation token cleared.", "success");
  } catch (error) {
    toast(`Could not clear the token: ${error.message}`, "error");
  } finally {
    setBusy(button, false);
  }
}

function toast(message, kind = "") {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast${kind ? ` ${kind}` : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.add("hidden"), 5000);
}

async function api(path, options = {}) {
  const isDiagnosticRequest = path.startsWith("/api/logs");
  try {
    const response = await fetch(path, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-Canvas-Api-Token": API_TOKEN,
        ...(options.headers || {}),
      },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok && response.status !== 202) {
      const error = new Error(body.error || `GitHub request failed with HTTP ${response.status}.`);
      error.details = body.details;
      throw error;
    }
    return body;
  } catch (error) {
    if (error.details !== undefined) throw error;
    throw new Error(`Request failed: ${error.message}`);
  } finally {
    if (!isDiagnosticRequest) requestDiagnosticRefresh();
  }
}

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
  const list = $("#diagnosticList");
  const openEntryIds = new Set(
    $$(".diagnostic-entry[open]", list).map((entry) => Number(entry.dataset.entryId)),
  );
  const wasNearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 32;
  const count = state.diagnosticEntries.length;
  $("#diagnosticCount").textContent = `${count} entr${count === 1 ? "y" : "ies"}`;
  $("#diagnosticCount").className = `status-chip ${count ? "success" : "neutral"}`;
  if (!count) {
    list.innerHTML = `<div class="empty-list"><strong>No API activity yet</strong><span>Requests will appear here as you use the canvas.</span></div>`;
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
  $$(".diagnostic-entry", list).forEach((entry) => {
    entry.open = openEntryIds.has(Number(entry.dataset.entryId));
  });
  if ($("#diagnosticPanel").open && wasNearBottom) list.scrollTop = list.scrollHeight;
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
    $("#diagnosticHint").textContent = `Held only in memory for this canvas. Credentials are redacted. Retaining ${result.retained || 0} of ${result.maxEntries || MAX_CLIENT_DIAGNOSTICS} entries.`;
    if (additions.length || !state.diagnosticEntries.length) renderDiagnostics();
  } catch (error) {
    $("#diagnosticHint").textContent = `Could not refresh activity: ${error.message}`;
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
    toast(successMessage, "success");
  } catch {
    toast("Clipboard access failed. Expand the entry and copy it manually.", "error");
  }
}

async function copyLatestResponse() {
  const latest = [...state.diagnosticEntries].reverse()
    .find((entry) => entry.response !== undefined);
  if (!latest) {
    toast("No API response is available yet.", "error");
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
    $("#diagnosticHint").textContent = "Activity cleared. New requests will appear here.";
  } catch (error) {
    toast(`Could not clear API activity: ${error.message}`, "error");
  } finally {
    state.diagnosticClearing = false;
  }
}

async function openDiagnostics() {
  $("#diagnosticPanel").open = true;
  startDiagnosticPolling();
  await refreshDiagnostics();
}

function setBusy(button, busy, busyText) {
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function setSegment(containerId, value) {
  const container = $(`#${containerId}`);
  $$("button", container).forEach((button) => button.classList.toggle("active", button.dataset.value === value));
}

function updateScopeUi() {
  const organizationTarget = $("#organizationTargetOption");
  organizationTarget.classList.toggle("hidden", !state.previewFeaturesEnabled);
  $("#targetType").classList.toggle("single-option", !state.previewFeaturesEnabled);
  $("#previewFeatures").checked = state.previewFeaturesEnabled;
  if (!state.previewFeaturesEnabled && state.targetType === "organization") {
    state.targetType = "enterprise";
    state.targetSlug = "";
    $("#targetSlug").value = "";
  }
  setSegment("sourceType", state.sourceType);
  setSegment("targetType", state.targetType);
  const sourceEnterprise = state.sourceType === "enterprise";
  const targetEnterprise = state.targetType === "enterprise";
  $("#sourceSlugLabel").textContent = sourceEnterprise ? "Enterprise slug" : "Organization login";
  $("#sourceSlug").placeholder = sourceEnterprise ? "octo-enterprise" : "octo-organization";
  $("#targetSlugLabel").textContent = targetEnterprise ? "Enterprise slug" : "Organization login";
  $("#targetSlug").placeholder = targetEnterprise ? "octo-enterprise" : "octo-organization";
  $("#targetMode").textContent = targetEnterprise ? "GA" : "Private preview";
  $("#targetMode").className = `status-chip ${targetEnterprise ? "success" : "preview"}`;
  $("#sourceMode").textContent = "GA";
  $("#sourceMode").className = "status-chip success";
  $("#sourceMode").title = `${sourceEnterprise ? "Enterprise" : "Organization"} loading is GA.`;
  $("#targetMessage").textContent = targetEnterprise
    ? "Requires enterprise_innersource_vulnerabilities:write."
    : "Private preview feature. Requires organization_innersource_vulnerabilities:write and account enablement.";
  renderCredentialState();
  updateDeploySummary();
}

function currentSource() {
  return { type: state.sourceType, slug: $("#sourceSlug").value.trim() };
}

function currentTarget() {
  return { type: state.targetType, slug: $("#targetSlug").value.trim() };
}

function credentialMatchesTarget(credential, target = currentTarget()) {
  return credential?.scope?.type === target.type
    && String(credential.scope.slug || "").toLowerCase() === target.slug.toLowerCase();
}

function renderCredentialState() {
  const message = $("#credentialMessage");
  const clearButton = $("#clearGeneratedToken");
  let credential = state.generatedDeployToken;
  if (credential && Date.parse(credential.expiresAt) <= Date.now() + 30_000) {
    state.generatedDeployToken = null;
    credential = null;
  }
  renderAuthContext();

  clearButton.classList.toggle("hidden", !credential);
  if (!credential) {
    message.textContent = "No generated token is held by this canvas.";
    message.className = "inline-message credential-message";
    return;
  }

  const expires = new Date(credential.expiresAt).toLocaleString();
  const scopeLabel = `${credential.scope.type}/${credential.scope.slug}`;
  if (credentialMatchesTarget(credential)) {
    message.textContent = `Token ready for ${scopeLabel} via installation ${credential.installationId}; expires ${expires}.`;
    message.className = "inline-message credential-message success";
  } else {
    message.textContent = `The generated token is for ${scopeLabel} and will not be used for the current target.`;
    message.className = "inline-message credential-message error";
  }
}

function localDateTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function isoDateTime(value) {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function nowLocal() {
  return localDateTime(new Date().toISOString());
}

function emptyOsv() {
  return {
    schema_version: "1.4.0",
    id: "",
    modified: new Date().toISOString(),
    summary: "",
    details: "",
    severity: [],
    affected: [{
      package: { ecosystem: "npm", name: "" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "" }] }],
    }],
    published: new Date().toISOString(),
  };
}

function severityEntry(osv, type) {
  return (osv.severity || []).find((entry) => entry.type === type)?.score || "";
}

function createAffectedItem(affected = {}) {
  const fragment = $("#affectedTemplate").content.cloneNode(true);
  const item = $(".affected-item", fragment);
  const ecosystemSelect = $('[data-field="ecosystem"]', item);
  ecosystemSelect.innerHTML = ECOSYSTEMS.map((ecosystem) =>
    `<option value="${escapeHtml(ecosystem)}">${escapeHtml(ecosystem)}</option>`
  ).join("");
  ecosystemSelect.value = affected.package?.ecosystem || "npm";
  $('[data-field="name"]', item).value = affected.package?.name || "";

  const versions = Array.isArray(affected.versions) ? affected.versions : [];
  const range = affected.ranges?.[0];
  const mode = versions.length ? "versions" : "range";
  const radioGroup = `range-mode-${crypto.randomUUID()}`;
  $$('[data-field="mode"]', item).forEach((radio) => {
    radio.name = radioGroup;
    radio.checked = radio.value === mode;
    radio.addEventListener("change", () => updateAffectedMode(item));
  });

  if (range) {
    $('[data-field="rangeType"]', item).value = range.type || "ECOSYSTEM";
    const introduced = range.events?.find((event) => event.introduced != null)?.introduced || "";
    const fixed = range.events?.find((event) => event.fixed != null)?.fixed;
    const lastAffected = range.events?.find((event) => event.last_affected != null)?.last_affected;
    $('[data-field="introduced"]', item).value = introduced;
    $('[data-field="upperKind"]', item).value = fixed != null ? "fixed" : lastAffected != null ? "last_affected" : "";
    $('[data-field="upperVersion"]', item).value = fixed ?? lastAffected ?? "";
  }
  $('[data-field="versions"]', item).value = versions.join(", ");
  $("[data-remove]", item).addEventListener("click", () => {
    item.remove();
    if (!$("#affectedList").children.length) createAffectedItem({ package: { ecosystem: "npm", name: "" } });
    refreshRepeaterCounts();
  });
  $("#affectedList").appendChild(item);
  updateAffectedMode(item);
  refreshRepeaterCounts();
}

function updateAffectedMode(item) {
  const mode = $('[data-field="mode"]:checked', item)?.value || "range";
  $("[data-range-fields]", item).classList.toggle("hidden", mode !== "range");
  $("[data-version-fields]", item).classList.toggle("hidden", mode !== "versions");
}

function createReferenceItem(reference = {}) {
  const fragment = $("#referenceTemplate").content.cloneNode(true);
  const item = $(".reference-item", fragment);
  $('[data-field="type"]', item).value = reference.type || "WEB";
  $('[data-field="url"]', item).value = reference.url || "";
  $("[data-remove]", item).addEventListener("click", () => {
    item.remove();
    refreshRepeaterCounts();
  });
  $("#referenceList").appendChild(item);
  refreshRepeaterCounts();
}

function refreshRepeaterCounts() {
  $$(".affected-item").forEach((item, index) => {
    $("[data-index]", item).textContent = index + 1;
  });
  $("#affectedCount").textContent = $$(".affected-item").length;
  $("#referenceCount").textContent = $$(".reference-item").length;
}

function readAffected() {
  return $$(".affected-item").map((item) => {
    const affected = {
      package: {
        ecosystem: $('[data-field="ecosystem"]', item).value,
        name: $('[data-field="name"]', item).value.trim(),
      },
    };
    const mode = $('[data-field="mode"]:checked', item)?.value || "range";
    if (mode === "versions") {
      affected.versions = $('[data-field="versions"]', item).value.split(",").map((value) => value.trim()).filter(Boolean);
      return affected;
    }
    const events = [];
    const introduced = $('[data-field="introduced"]', item).value.trim();
    const upperKind = $('[data-field="upperKind"]', item).value;
    const upperVersion = $('[data-field="upperVersion"]', item).value.trim();
    if (introduced) events.push({ introduced });
    if (upperKind && upperVersion) events.push({ [upperKind]: upperVersion });
    affected.ranges = [{ type: $('[data-field="rangeType"]', item).value, events }];
    return affected;
  });
}

function readReferences() {
  return $$(".reference-item").map((item) => ({
    type: $('[data-field="type"]', item).value,
    url: $('[data-field="url"]', item).value.trim(),
  })).filter((reference) => reference.url);
}

function buildOsv({ updateModified = false } = {}) {
  const v3 = $("#cvssV3").value.trim();
  const v4 = $("#cvssV4").value.trim();
  const aliases = $("#aliases").value.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean);
  const advisory = {
    schema_version: "1.4.0",
    id: $("#advisoryId").value.trim(),
    modified: updateModified ? new Date().toISOString() : ($("#advisoryForm").dataset.modified || new Date().toISOString()),
    summary: $("#summary").value.trim(),
    details: $("#details").value.trim(),
    severity: [
      ...(v3 ? [{ type: "CVSS_V3", score: v3 }] : []),
      ...(v4 ? [{ type: "CVSS_V4", score: v4 }] : []),
    ],
    affected: readAffected(),
  };
  if (aliases.length) advisory.aliases = aliases;
  const references = readReferences();
  if (references.length) advisory.references = references;
  const published = isoDateTime($("#published").value);
  if (published) advisory.published = published;
  if ($("#withdrawnEnabled").checked) {
    const withdrawn = isoDateTime($("#withdrawn").value);
    if (withdrawn) advisory.withdrawn = withdrawn;
  }
  const score = cvssV3BaseScore(parseCvssV3Vector(v3));
  const severity = severityForScore(score);
  if (severity !== "unknown" && severity !== "none") {
    advisory.database_specific = { severity: severity === "moderate" ? "Moderate" : severity[0].toUpperCase() + severity.slice(1) };
  }
  return advisory;
}

function populateForm(osv, item = null) {
  const advisory = structuredClone(osv || emptyOsv());
  $("#advisoryForm").dataset.modified = advisory.modified || new Date().toISOString();
  $("#advisoryId").value = advisory.id || "";
  $("#aliases").value = (advisory.aliases || []).join(", ");
  $("#summary").value = advisory.summary || "";
  $("#details").value = advisory.details || "";
  $("#published").value = localDateTime(advisory.published);
  $("#withdrawnEnabled").checked = Boolean(advisory.withdrawn);
  $("#withdrawn").disabled = !advisory.withdrawn;
  $("#withdrawn").value = localDateTime(advisory.withdrawn);
  $("#cvssV3").value = severityEntry(advisory, "CVSS_V3");
  $("#cvssV4").value = severityEntry(advisory, "CVSS_V4");

  $("#affectedList").innerHTML = "";
  (advisory.affected?.length ? advisory.affected : emptyOsv().affected).forEach(createAffectedItem);
  $("#referenceList").innerHTML = "";
  (advisory.references || []).forEach(createReferenceItem);
  refreshRepeaterCounts();

  state.selectedGhsaId = item?.ghsaId || null;
  state.selectedPermalink = item?.permalink || null;
  state.selectedSourceScope = item?.sourceScope
    ? { type: item.sourceScope.type, slug: item.sourceScope.slug }
    : null;
  $("#externalIdNotice").classList.toggle("hidden", !item);
  $("#externalIdNoticeText").textContent = item
    ? `GitHub lists this advisory as ${item.ghsaId} but does not return the OSV ID originally used to sync it. Enter that exact ID above to update or withdraw it. A different ID creates a separate advisory.`
    : "";
  $("#advisoryIdHelp").textContent = item
    ? "Replace the GitHub ID with the exact OSV ID originally used to sync this advisory."
    : "Stable OSV identifier used to create, update, or withdraw this advisory.";
  state.jsonDirty = false;
  $("#jsonPreview").value = JSON.stringify(advisory, null, 2);
  $("#advisoryLink").classList.toggle("hidden", !state.selectedPermalink);
  $("#loadDocsSample").classList.toggle("hidden", Boolean(item));
  if (state.selectedPermalink) $("#advisoryLink").href = state.selectedPermalink;
  $("#editorTitle").textContent = item?.ghsaId || (advisory.id ? advisory.id : "New innersource advisory");
  $("#editorSubtitle").textContent = item
    ? `${item.sourceScope.type}/${item.sourceScope.slug} - ${item.sourceRanges.length} vulnerable range${item.sourceRanges.length === 1 ? "" : "s"}`
    : "Draft an OSV 1.4 advisory for GitHub Dependabot.";
  $("#summaryLength").textContent = new TextEncoder().encode($("#summary").value).length;
  applyCvssVectorToMetrics($("#cvssV3").value);
  updateCvss();
  renderAdvisoryList();
  hideValidation();
}

function metricValues() {
  const metrics = {};
  for (const key of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    const selected = $(`input[name="${key}"]:checked`);
    if (selected) metrics[key] = selected.value;
  }
  return metrics;
}

function applyCvssVectorToMetrics(vector) {
  const metrics = parseCvssV3Vector(vector);
  if (!metrics) return;
  for (const [key, value] of Object.entries(metrics)) {
    const radio = $(`input[name="${key}"][value="${value}"]`);
    if (radio) radio.checked = true;
  }
}

function updateCvss(fromMetrics = false) {
  if (fromMetrics) {
    const vector = cvssV3Vector(metricValues());
    if (vector) $("#cvssV3").value = vector;
  }
  const metrics = parseCvssV3Vector($("#cvssV3").value);
  const score = cvssV3BaseScore(metrics);
  const severity = severityForScore(score);
  $("#cvssScore").textContent = score == null ? "--" : score.toFixed(1);
  $("#cvssSeverity").textContent = severity;
  $("#severityBadge").textContent = severity;
  $("#severityBadge").className = `severity-badge ${severity}`;
}

function advisoryMatches(item) {
  const query = $("#advisorySearch").value.trim().toLowerCase();
  const severity = $("#severityFilter").value;
  if (severity && item.severity !== severity) return false;
  if (!$("#includeWithdrawn").checked && item.withdrawn) return false;
  if (!query) return true;
  return [
    item.ghsaId,
    item.summary,
    ...item.sourceRanges.flatMap((range) => [range.ecosystem, range.package, range.range]),
  ].join(" ").toLowerCase().includes(query);
}

function renderAdvisoryList() {
  const list = $("#advisoryList");
  const filtered = state.advisories.filter(advisoryMatches);
  if (!filtered.length) {
    list.innerHTML = `<div class="empty-list"><strong>${state.advisories.length ? "No matching advisories" : "No advisories loaded"}</strong><span>${state.advisories.length ? "Adjust the filters above." : "Load a source or create a new advisory."}</span></div>`;
    return;
  }
  list.innerHTML = filtered.map((item) => {
    const packages = [...new Set(item.sourceRanges.map((range) => range.package))].slice(0, 2);
    const date = item.updatedAt ? new Date(item.updatedAt).toLocaleDateString() : "";
    return `
      <div class="advisory-item${state.selectedGhsaId === item.ghsaId ? " active" : ""}">
        <button class="advisory-select" type="button" data-ghsa="${escapeHtml(item.ghsaId)}">
          <span class="id">${escapeHtml(item.ghsaId)}</span>
          <span class="summary">${escapeHtml(item.summary)}</span>
          <span class="meta">
            <span class="package-tags">${packages.map((name) => `<span class="package-tag">${escapeHtml(name)}</span>`).join("")}</span>
            <span>${escapeHtml(item.severity)}${item.withdrawn ? " - withdrawn" : ""}${date ? ` - ${escapeHtml(date)}` : ""}</span>
          </span>
        </button>
        ${item.permalink ? `<a class="advisory-link" href="${escapeHtml(item.permalink)}" target="_blank" rel="noreferrer" title="Open advisory on GitHub" aria-label="Open ${escapeHtml(item.ghsaId)} on GitHub">↗</a>` : ""}
      </div>`;
  }).join("");
  $$(".advisory-select", list).forEach((button) => button.addEventListener("click", () => {
    const item = state.advisories.find((candidate) => candidate.ghsaId === button.dataset.ghsa);
    if (item) populateForm(item.osv, item);
  }));
}

async function loadSource() {
  const button = $("#loadSource");
  const scope = currentSource();
  if (!scope.slug) {
    $("#sourceMessage").textContent = `Enter an ${scope.type} slug.`;
    $("#sourceMessage").className = "inline-message error";
    return;
  }
  setBusy(button, true, "Loading...");
  $("#sourceMessage").textContent = `Querying ${scope.type}/${scope.slug}...`;
  $("#sourceMessage").className = "inline-message";
  try {
    const result = await api("/api/list-advisories", {
      method: "POST",
      body: JSON.stringify({ scope }),
    });
    state.advisories = result.advisories || [];
    state.sourceSlug = scope.slug;
    $("#sourceCount").textContent = `${state.advisories.length} advisories`;
    $("#sourceCount").className = "status-chip success";
    $("#sourceSummary").textContent = `${scope.type}/${scope.slug}`;
    $("#sourceMessage").textContent = `Loaded ${state.advisories.length} advisories.`;
    $("#sourceMessage").className = "inline-message success";
    renderAdvisoryList();
    const requestedId = new URL(location.href).searchParams.get("advisoryId");
    const first = state.advisories.find((item) => item.ghsaId === requestedId) || state.advisories[0];
    if (first) populateForm(first.osv, first);
    toast(`Loaded ${state.advisories.length} advisories from ${scope.slug}.`, "success");
  } catch (error) {
    $("#sourceMessage").textContent = error.message;
    $("#sourceMessage").className = "inline-message error";
    toast(`Load failed: ${error.message}`, "error");
  } finally {
    setBusy(button, false);
  }
}

function showValidation(validation) {
  const panel = $("#validationPanel");
  const messages = [
    ...(validation.errors || []).map((message) => ({ kind: "Error", message })),
    ...(validation.warnings || []).map((message) => ({ kind: "Warning", message })),
  ];
  panel.className = `validation-panel ${validation.valid ? "success" : "error"}`;
  $("#validationTitle").textContent = validation.valid
    ? (messages.length ? "Valid with warnings" : "Advisory is valid")
    : `${validation.errors.length} validation error${validation.errors.length === 1 ? "" : "s"}`;
  $("#validationMessages").innerHTML = messages.map((entry) =>
    `<li><strong>${entry.kind}:</strong> ${escapeHtml(entry.message)}</li>`
  ).join("");
}

function hideValidation() {
  $("#validationPanel").className = "validation-panel hidden";
}

async function validateAdvisory() {
  const advisory = buildOsv();
  const local = validateOsv(advisory);
  if (state.selectedGhsaId && advisory.id.toLowerCase() === state.selectedGhsaId.toLowerCase()) {
    local.errors.push(
      `GitHub's listing API does not expose the original OSV ID for ${state.selectedGhsaId}. `
      + "Enter the exact ID used when this advisory was first synced to update it. "
      + "Using a different ID creates a separate advisory.",
    );
    local.valid = false;
  }
  if (!local.valid) {
    showValidation(local);
    return local;
  }
  try {
    const remote = await api("/api/validate", {
      method: "POST",
      body: JSON.stringify({ advisory }),
    });
    showValidation(remote);
    return remote;
  } catch (error) {
    const validation = error.details || { valid: false, errors: [error.message], warnings: [] };
    showValidation(validation);
    return validation;
  }
}

function updateDeploySummary() {
  const target = currentTarget();
  $("#deploySummary").textContent = target.slug
    ? `Target: ${target.type}/${target.slug}${target.type === "organization" ? " (preview)" : ""}`
    : "Choose a deployment target";
}

async function openDeployModal() {
  const target = currentTarget();
  if (!target.slug) {
    toast(`Enter a target ${target.type} slug.`, "error");
    return;
  }
  const validation = await validateAdvisory();
  if (!validation?.valid) {
    toast("Fix validation errors before deployment.", "error");
    return;
  }
  const authentication = $("#deployToken").value.trim()
    ? "Pasted installation token"
    : credentialMatchesTarget(state.generatedDeployToken)
      ? `Generated token (installation ${state.generatedDeployToken.installationId})`
      : state.deployTokenConfigured
        ? "GH_INNERSOURCE_TOKEN"
        : "";
  if (!authentication) {
    toast("Paste or generate a GitHub App installation token before deployment.", "error");
    return;
  }
  const advisory = buildOsv({ updateModified: true });
  const source = state.selectedSourceScope;
  const crossScope = state.selectedGhsaId
    && source
    && (source.type !== target.type || source.slug.toLowerCase() !== target.slug.toLowerCase());
  const operation = advisory.withdrawn ? "withdraw" : crossScope ? "create copy" : state.selectedGhsaId ? "create or update" : "create";
  $("#deployModalBody").innerHTML = `
    <dl class="modal-body-grid">
      <dt>Operation</dt><dd>${escapeHtml(operation)}</dd>
      <dt>Advisory</dt><dd><code>${escapeHtml(advisory.id)}</code></dd>
      <dt>Summary</dt><dd>${escapeHtml(advisory.summary)}</dd>
      <dt>Target</dt><dd><code>${escapeHtml(target.type)}/${escapeHtml(target.slug)}</code></dd>
      <dt>Authentication</dt><dd>${escapeHtml(authentication)}</dd>
      <dt>Affected entries</dt><dd>${advisory.affected.length}</dd>
    </dl>
    ${target.type === "organization" ? `<div class="preview-warning"><strong>Preview target:</strong> Organization deployment is unpublished and returns 404 unless GitHub has enabled organization sync for this account.</div>` : ""}
  `;
  $("#deployModal").classList.remove("hidden");
}

async function deployAdvisory() {
  const button = $("#confirmDeploy");
  const target = currentTarget();
  const token = $("#deployToken").value.trim();
  const advisory = buildOsv({ updateModified: true });
  let jobId = "";
  setBusy(button, true, "Submitting...");
  try {
    const response = await api("/api/deploy", {
      method: "POST",
      body: JSON.stringify({ scope: target, advisory, token: token || undefined }),
    });
    jobId = response.job.id;
    $("#deployModal").classList.add("hidden");
    toast(`Sync job ${jobId} queued. Waiting for GitHub...`);
    const result = await pollSync(target, jobId, token);
    if (result.status === "error") throw new Error(result.error || "GitHub could not process the advisory.");
    const itemResult = result.results?.find((item) => item.external_id === advisory.id) || result.results?.[0];
    if (itemResult?.status === "error") throw new Error(itemResult.error || "Advisory sync failed.");
    const counts = `created ${result.created || 0}, updated ${result.updated || 0}, withdrawn ${result.withdrawn || 0}`;
    toast(`Sync complete: ${counts}.`, "success");
    $("#targetMessage").textContent = `Last sync complete: ${counts}.`;
    $("#targetMessage").className = "inline-message success";
  } catch (error) {
    const jobLabel = jobId ? `Sync job ${jobId}: ` : "";
    toast(`Deployment failed: ${jobLabel}${error.message}`, "error");
    $("#targetMessage").textContent = `${jobLabel}${error.message}`;
    $("#targetMessage").className = "inline-message error";
    await openDiagnostics();
  } finally {
    setBusy(button, false);
  }
}

async function pollSync(scope, jobId, token) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    const response = await api("/api/sync-status", {
      method: "POST",
      body: JSON.stringify({ scope, jobId, token: token || undefined }),
    });
    if (!response.pending) return response.result;
  }
  throw new Error(`Sync job ${jobId} is still processing. Check its status later.`);
}

function refreshJson() {
  $("#jsonPreview").value = JSON.stringify(buildOsv(), null, 2);
  state.jsonDirty = false;
}

function loadDocsSample() {
  populateForm(createGitHubDocsSampleOsv());
  toast("Loaded the GitHub Docs sample. Update its example ID and package before deployment.", "success");
}

function applyJson() {
  try {
    const advisory = JSON.parse($("#jsonPreview").value);
    populateForm(advisory);
    toast("OSV JSON applied to the form.", "success");
  } catch (error) {
    toast(`Invalid JSON: ${error.message}`, "error");
  }
}

function downloadJson() {
  const advisory = buildOsv();
  const fileName = `${advisory.id || "innersource-advisory"}.json`.replace(/[^A-Za-z0-9._-]/g, "-");
  const blob = new Blob([`${JSON.stringify(advisory, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function copyJson() {
  refreshJson();
  try {
    await navigator.clipboard.writeText($("#jsonPreview").value);
    toast("OSV JSON copied.", "success");
  } catch {
    $("#jsonPreview").select();
    toast("Select and copy the JSON manually.");
  }
}

function bindEvents() {
  for (const [containerId, stateKey] of [["sourceType", "sourceType"], ["targetType", "targetType"]]) {
    $$(`#${containerId} button`).forEach((button) => button.addEventListener("click", () => {
      if (stateKey === "targetType" && button.dataset.value === "organization" && !state.previewFeaturesEnabled) return;
      state[stateKey] = button.dataset.value;
      updateScopeUi();
    }));
  }
  $("#previewFeatures").addEventListener("change", () => {
    const resetOrganizationTarget = !$("#previewFeatures").checked && state.targetType === "organization";
    state.previewFeaturesEnabled = $("#previewFeatures").checked;
    updateScopeUi();
    if (resetOrganizationTarget) {
      toast("Organization deployment hidden. Choose an enterprise target.", "success");
    }
  });
  $("#sourceSlug").addEventListener("input", () => { state.sourceSlug = $("#sourceSlug").value.trim(); });
  $("#deployToken").addEventListener("input", renderAuthContext);
  $("#targetSlug").addEventListener("input", () => {
    state.targetSlug = $("#targetSlug").value.trim();
    renderCredentialState();
    updateDeploySummary();
  });
  $("#appPrivateKey").addEventListener("change", () => {
    const file = $("#appPrivateKey").files?.[0];
    $("#privateKeyHint").textContent = file
      ? `Selected ${file.name}. The file is read only when you generate a token.`
      : "Select the private key downloaded from the GitHub App settings page.";
  });
  $("#generateDeployToken").addEventListener("click", generateDeployToken);
  $("#clearGeneratedToken").addEventListener("click", clearGeneratedToken);
  $("#loadSource").addEventListener("click", loadSource);
  $("#newAdvisory").addEventListener("click", () => populateForm(emptyOsv()));
  $("#advisorySearch").addEventListener("input", renderAdvisoryList);
  $("#severityFilter").addEventListener("change", renderAdvisoryList);
  $("#includeWithdrawn").addEventListener("change", renderAdvisoryList);

  $$(".tabs button").forEach((button) => button.addEventListener("click", () => {
    $$(".tabs button").forEach((candidate) => candidate.classList.toggle("active", candidate === button));
    $$(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === button.dataset.tab));
    if (button.dataset.tab === "json" && !state.jsonDirty) refreshJson();
  }));

  $("#addAffected").addEventListener("click", () => createAffectedItem({ package: { ecosystem: "npm", name: "" } }));
  $("#addReference").addEventListener("click", () => createReferenceItem());
  $("#withdrawnEnabled").addEventListener("change", () => {
    $("#withdrawn").disabled = !$("#withdrawnEnabled").checked;
    if ($("#withdrawnEnabled").checked && !$("#withdrawn").value) $("#withdrawn").value = nowLocal();
  });
  $("#summary").addEventListener("input", () => {
    $("#summaryLength").textContent = new TextEncoder().encode($("#summary").value).length;
  });

  $$("#cvssMetrics input").forEach((input) => input.addEventListener("change", () => updateCvss(true)));
  $("#cvssV3").addEventListener("change", () => {
    applyCvssVectorToMetrics($("#cvssV3").value);
    updateCvss();
  });
  $("#cvssV3").addEventListener("input", () => updateCvss());

  $("#refreshJson").addEventListener("click", refreshJson);
  $("#loadDocsSample").addEventListener("click", loadDocsSample);
  $("#copyJson").addEventListener("click", copyJson);
  $("#applyJson").addEventListener("click", applyJson);
  $("#jsonPreview").addEventListener("input", () => { state.jsonDirty = true; });
  $("#validateAdvisory").addEventListener("click", validateAdvisory);
  $("#downloadJson").addEventListener("click", downloadJson);
  $("#deployAdvisory").addEventListener("click", openDeployModal);
  $("#cancelDeploy").addEventListener("click", () => $("#deployModal").classList.add("hidden"));
  $("#confirmDeploy").addEventListener("click", deployAdvisory);
  $("#deployModal").addEventListener("click", (event) => {
    if (event.target === $("#deployModal")) $("#deployModal").classList.add("hidden");
  });
  $("#diagnosticPanel").addEventListener("toggle", () => {
    if ($("#diagnosticPanel").open) startDiagnosticPolling();
    else stopDiagnosticPolling();
  });
  $("#refreshDiagnostics").addEventListener("click", refreshDiagnostics);
  $("#copyLatestResponse").addEventListener("click", copyLatestResponse);
  $("#copyDiagnostics").addEventListener("click", copyDiagnostics);
  $("#clearDiagnostics").addEventListener("click", clearDiagnostics);
}

async function loadContext() {
  try {
    const context = await api("/api/context");
    state.authContext = context;
    state.deployTokenConfigured = context.deployTokenConfigured;
    state.generatedDeployToken = context.generatedDeployToken;
    $("#targetMessage").textContent = context.deployTokenConfigured
      ? "GH_INNERSOURCE_TOKEN is configured."
      : "Paste a token, generate one below, or set GH_INNERSOURCE_TOKEN.";
    renderCredentialState();
  } catch (error) {
    state.authContext = { error: error.message };
    renderAuthContext();
  }
}

function applyOpenInput() {
  const params = new URL(location.href).searchParams;
  if (["enterprise", "organization"].includes(params.get("sourceType"))) state.sourceType = params.get("sourceType");
  const requestedTargetType = params.get("targetType");
  if (["enterprise", "organization"].includes(requestedTargetType)) state.targetType = requestedTargetType;
  state.previewFeaturesEnabled = params.get("previewFeatures") === "true" || requestedTargetType === "organization";
  $("#sourceSlug").value = params.get("sourceSlug") || "";
  $("#targetSlug").value = params.get("targetSlug") || "";
  state.sourceSlug = $("#sourceSlug").value;
  state.targetSlug = $("#targetSlug").value;
  updateScopeUi();
}

async function init() {
  bindEvents();
  applyOpenInput();
  populateForm(emptyOsv());
  await loadContext();
  await refreshDiagnostics();
  if ($("#sourceSlug").value) await loadSource();
}

init();
