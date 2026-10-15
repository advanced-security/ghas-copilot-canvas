import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	CONTROLS,
	EMPTY_TOTALS,
	RING_RADIUS,
	COPILOT_ASSIGNEE,
	alertUrl,
	assignCopilotRequest,
	auditBrief,
	buildLiveFindings,
	campaignProjection,
	canAssignCopilot,
	complianceModel,
	complianceOfflineAnswer,
	compliancePrompt,
	copilotPromptForFinding,
	copyCorpus,
	criticalHighIds,
	escapeHtml,
	explainPromptForFinding,
	findBannedPhrase,
	findingBrief,
	findingId,
	isCopilotLogin,
	layoutFindings,
	parseRemoteRepo,
	pickRadarAlert,
	radarAttachment,
	radarFindingUrl,
	radarKpis,
	radarOfflineAnswer,
	radarPrompt,
	remediationProjection,
	repoEvidence,
	stripAlerts,
	wantsChange,
} from "./logic.mjs";
import { CANVAS_IDS, renderPage } from "./pages.mjs";

const REPO = "acme/widgets";
const SQL = findingId("cs", "js/sql-injection");
const PATH = findingId("cs", "js/path-injection");
const UNPINNED = findingId("cs", "actions/unpinned-tag");
const PERMISSIONS = findingId("cs", "actions/excessive-permissions");
const TOKEN = findingId("sec", "github_personal_access_token");
const LODASH = findingId("dep", "npm/lodash");
const MINIMIST = findingId("dep", "npm/minimist");

const cs = (number, rule, severity, path, line, ref = "refs/heads/main") => ({
	number,
	html_url: `https://github.com/${REPO}/security/code-scanning/${number}`,
	rule: { id: rule, severity: "error", security_severity_level: severity, description: rule },
	most_recent_instance: { ref, location: { path, start_line: line } },
});
const dep = (number, name, severity, manifest = "package-lock.json") => ({
	number,
	dependency: { package: { ecosystem: "npm", name }, manifest_path: manifest },
	security_advisory: { severity },
});
const secret = (number, type = "github_personal_access_token", name = "GitHub Personal Access Token") => ({
	number, secret_type: type, secret_type_display_name: name,
});

const RAW = {
	defaultBranch: "main",
	code: [
		cs(1, "js/sql-injection", "critical", "src/app.js", 52),
		cs(2, "js/path-injection", "high", "src/files.js", 20),
		cs(3, "js/path-injection", "high", "src/files.js", 44),
		cs(4, "actions/unpinned-tag", "medium", ".github/workflows/ci.yml", 8),
		cs(5, "actions/excessive-permissions", "medium", ".github/workflows/ci.yml", 3),
	],
	dependabot: [
		dep(1, "lodash", "high"), dep(2, "lodash", "high"), dep(3, "lodash", "medium"),
		dep(4, "minimist", "critical"), dep(5, "tiny", "low"), dep(6, "small", "medium"),
	],
	secrets: [secret(7)],
};
const TOTALS = { codeScanning: 5, dependabot: 6, secretScanning: 1, asOf: "2026-01-01 10:00" };
const findings = () => buildLiveFindings(RAW);
const byId = (list, id) => list.find((f) => f.id === id);

function page(canvasId, state, tail = "") {
	const html = renderPage(canvasId, state);
	const script = html.split("<script>").at(-1).replace("</script>\n</body>\n</html>", "");
	const drawn = [];
	const document = {
		getElementById(name) {
			if (name === "boot") return { textContent: html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/)[1] };
			return { set innerHTML(value) { drawn.push(value); }, querySelectorAll() { return []; } };
		},
	};
	// eslint-disable-next-line no-new-func
	new Function("document", "EventSource", `${script}\n${tail}`)(document, class {});
	return { html, drawn, out: drawn.at(-1) };
}

function radarState(extra = {}) {
	return {
		findings: layoutFindings(findings()),
		totals: TOTALS,
		kpis: radarKpis(findings(), TOTALS),
		source: "github",
		repo: REPO,
		threads: {},
		disclaimer: "Illustrative",
		...extra,
	};
}

function postureState(extra = {}) {
	return { ...complianceModel([], findings(), { totals: TOTALS, repo: REPO }), source: "github", threads: {}, pending: null, ...extra };
}

test("live radar groups GitHub alerts under generic ids and drops alert details", () => {
	const raw = stripAlerts({
		...RAW,
		secrets: [{ ...secret(7), secret: "never-kept" }],
		dependabot: RAW.dependabot.map((a) => ({ ...a, security_advisory: { ...a.security_advisory, description: "dropped" } })),
	});
	assert.equal(JSON.stringify(raw).includes("never-kept"), false);
	assert.equal(JSON.stringify(raw).includes("dropped"), false);
	const list = buildLiveFindings({ ...raw, defaultBranch: "main" });
	const ids = list.map((f) => f.id);
	assert.equal(ids[0], SQL);
	for (const id of [PATH, UNPINNED, TOKEN, LODASH, MINIMIST, "dep-rest"]) {
		assert.ok(ids.includes(id), id);
	}
	assert.equal(byId(list, PATH).count, 2);
	assert.equal(byId(list, PATH).severity, "high");
	assert.deepEqual(byId(list, LODASH).bySeverity, { critical: 0, high: 2, medium: 1, low: 0 });
	const rest = byId(list, "dep-rest");
	assert.equal(rest.count, 2);
	assert.equal(rest.packages, 2);
	assert.deepEqual(rest.packageNames.sort(), ["small", "tiny"]);
	assert.equal(list.reduce((sum, f) => sum + f.count, 0), 12);
	assert.deepEqual(byId(list, UNPINNED).controlIds, ["change", "supply"]);
	assert.deepEqual(byId(list, PERMISSIONS).controlIds, ["change"]);
	assert.deepEqual(byId(list, SQL).controlIds, ["vuln"]);
	assert.deepEqual(byId(list, TOKEN).controlIds, ["secrets"]);
	const kpis = radarKpis(list, TOTALS);
	assert.equal(kpis.open, 12);
	assert.equal(kpis.mapped, 12);
	assert.equal(kpis.criticalHigh, 7);
	assert.equal(kpis.secrets, 1);
	assert.equal(kpis.quickWinBumps, 2);
	const laid = layoutFindings(list);
	assert.equal(laid.length, list.length);
	for (const f of laid) assert.ok(Number.isFinite(f.x) && Number.isFinite(f.y), f.id);
});

test("finding IDs preserve complete source keys despite ecosystem, punctuation, case and truncation collisions", () => {
	const keys = ["shared", "Shared", "a/b", "a-b", `${"x".repeat(60)}a`, `${"x".repeat(60)}b`];
	const raw = {
		code: keys.map((key, i) => cs(i + 1, key, "high", "src/app.js", i + 1)),
		secrets: keys.map((key, i) => secret(i + 1, key)),
		dependabot: ["npm", "pip"].flatMap((ecosystem) => keys.map((name, i) => ({
			...dep(i + 1, name, "high"), dependency: { package: { ecosystem, name }, manifest_path: "lockfile" },
		}))),
	};
	const list = buildLiveFindings(raw);
	assert.equal(list.length, keys.length * 4);
	assert.equal(new Set(list.map((finding) => finding.id)).size, list.length);
	assert.ok(list.every((finding) => /-[0-9a-f]{24}$/.test(finding.id)));
	const ids = new Map(list.map((finding) => [`${finding.source}/${finding.rule}`, finding.id]));
	const reordered = buildLiveFindings({
		code: [...raw.code].reverse(), secrets: [...raw.secrets].reverse(), dependabot: [...raw.dependabot].reverse(),
	});
	assert.deepEqual(new Map(reordered.map((finding) => [`${finding.source}/${finding.rule}`, finding.id])), ids);
	const layout = layoutFindings(list);
	assert.equal(new Set(layout.map(({ x, y }) => `${x},${y}`)).size, list.length);
	assert.notEqual(findingId("dep", "npm/shared"), findingId("dep", "pip/shared"));
	assert.notEqual(findingId("cs", "same"), findingId("sec", "same"));
});

test("radar attachments resolve canonical paths and reject traversal and symlink escapes", (t) => {
	const fixture = mkdtempSync(join(tmpdir(), "radar-attachment-"));
	t.after(() => rmSync(fixture, { recursive: true }));
	const root = join(fixture, "repo");
	const sibling = join(fixture, "repo-other");
	mkdirSync(join(root, "src"), { recursive: true });
	mkdirSync(sibling);
	writeFileSync(join(root, "src/app.js"), "safe fixture");
	writeFileSync(join(sibling, "outside.js"), "outside fixture");
	symlinkSync(root, join(fixture, "checkout"));
	symlinkSync(join(root, "src/app.js"), join(root, "internal.js"));
	symlinkSync(join(sibling, "outside.js"), join(root, "external.js"));
	symlinkSync(sibling, join(root, "external-dir"));
	const finding = { line: 52, path: "src/app.js" };
	const attachment = radarAttachment(finding, join(fixture, "checkout"));
	assert.equal(attachment.type, "file");
	assert.equal(attachment.path, realpathSync(join(root, finding.path)));
	assert.deepEqual(attachment.lineRange, { start: 34, end: 66 });
	assert.equal(radarAttachment({ ...finding, path: "internal.js" }, root).path, attachment.path);
	for (const path of ["../repo-other/outside.js", "src/../../repo-other/outside.js", "/", root, join(root, "src/app.js"), "external.js", "external-dir/outside.js"]) {
		assert.throws(() => radarAttachment({ ...finding, path }, root), /must stay inside the repository/, path);
	}
	assert.equal(radarAttachment({ ...finding, path: "not-in-checkout.js" }, root), null);
	assert.equal(radarAttachment({ path: "secret metadata" }, root), null);
});

test("Copilot assignment metadata belongs only to the representative alert", () => {
	const first = cs(1, "js/sql-injection", "high", "src/first.js", 10);
	const second = { ...cs(2, "js/sql-injection", "high", "src/second.js", 20), assignees: [{ login: COPILOT_ASSIGNEE }] };
	assert.equal(buildLiveFindings({ code: [second, first] })[0].copilot, null);
	const assignedFirst = { ...first, assignees: [{ login: COPILOT_ASSIGNEE }] };
	assert.deepEqual(buildLiveFindings({ code: [second, assignedFirst] })[0].copilot, { number: 1, url: first.html_url });
});

test("offline governance answers distinguish unknown evidence from verified controls", () => {
	const control = complianceModel().controls.find((item) => item.id === "secrets");
	for (const evidence of [
		control.evidence.map((item) => ({ ...item, status: null })),
		control.evidence.map((item, i) => ({ ...item, status: i === 0 ? true : null })),
		control.evidence.map((item, i) => ({ ...item, status: i === 0 ? false : null })),
	]) {
		const board = complianceOfflineAnswer("board", { ...control, evidence });
		assert.match(board, /Unverified supporting controls \(unknown status\)/);
		assert.doesNotMatch(board, /supporting controls are in place/);
		assert.match(complianceOfflineAnswer("auditor", { ...control, evidence }), /not checked/);
	}
	const verified = { ...control, evidence: control.evidence.map((item) => ({ ...item, status: true })) };
	assert.match(complianceOfflineAnswer("board", verified), /supporting controls are in place/);
	assert.match(complianceOfflineAnswer("plan", control), /verify .*status is unknown/);
});

test("an empty sync produces empty, finite models", () => {
	assert.deepEqual(buildLiveFindings(), []);
	assert.deepEqual(layoutFindings(), []);
	const kpis = radarKpis();
	assert.equal(kpis.open, 0);
	assert.equal(kpis.criticalHighPct, 0);
	assert.equal(kpis.supplyChainPct, 0);
	assert.deepEqual(criticalHighIds([]), []);
	const model = complianceModel();
	assert.equal(model.controls.length, 5);
	assert.deepEqual(model.totals, EMPTY_TOTALS);
	assert.ok(Number.isFinite(model.score));
	assert.equal(findBannedPhrase(auditBrief(model)), null);
	assert.match(auditBrief(model), /not synced yet/);
});

test("critical and high findings drive the preview and the projected score", () => {
	const list = findings();
	assert.deepEqual(criticalHighIds(list).sort(), list.filter((f) => ["critical", "high"].includes(f.severity)).map((f) => f.id).sort());
	assert.ok(!criticalHighIds(list).includes("dep-rest"));
	const today = complianceModel([], list, { totals: TOTALS });
	assert.equal(today.controls.length, 5);
	assert.ok(today.projected > today.score);
	assert.equal(today.lift, today.projected - today.score);
	for (const control of today.controls) {
		assert.ok(control.score >= 0 && control.score <= 20);
		assert.ok(control.projectedScore >= control.score);
	}
	for (const control of today.controls) for (const f of control.findings) assert.equal(f.url, null, "no repo, no link");
	const withRepo = complianceModel([], list, { totals: TOTALS, repo: REPO });
	for (const control of withRepo.controls) for (const f of control.findings) assert.match(f.url, /^https:\/\/github\.com\/acme\/widgets\/security\//);
	// Containing findings moves today; the projection never leaks into today.
	const lifted = complianceModel(criticalHighIds(list), list, { totals: TOTALS });
	assert.equal(lifted.score, today.projected);
	assert.equal(complianceModel([], list, { totals: TOTALS }).score, today.score);
});

test("campaign projections share scoring floors, evidence gaps, and overlapping theme deductions", () => {
	const list = [
		{ ...byId(findings(), UNPINNED), campaignCount: 1 },
		{ ...byId(findings(), PERMISSIONS), campaignCount: 1 },
		{ ...byId(findings(), LODASH) },
	];
	const model = complianceModel([], list);
	const projection = campaignProjection(model.controls, [UNPINNED, UNPINNED, LODASH, "closed"]);
	const resolved = complianceModel([UNPINNED], list);
	assert.equal(projection.score, resolved.score);
	assert.equal(projection.groups, 1);
	assert.equal(projection.alerts, 1);
	assert.equal(projection.upperBound, false);
	assert.equal(projection.controls.find((c) => c.id === "incident").lift, 0);
	assert.equal(model.score + projection.lift, projection.score);
	assert.ok(projection.lift > 0);

	const saturated = complianceModel([], Array.from({ length: 3 }, (_, i) => ({
		...byId(findings(), SQL), id: `critical-${i}`, count: 10, campaignCount: 1,
	})));
	assert.equal(campaignProjection(saturated.controls, ["critical-0"]).lift, 0);
	assert.ok(campaignProjection(saturated.controls, ["critical-0", "critical-1"]).lift > 0);
	assert.equal(campaignProjection(saturated.controls, []).score, saturated.score);
});

test("campaign projection retains branch exclusions and recalculates the remaining group severity", () => {
	const code = [
		cs(1, "js/remote-property-injection", "high", "a.ts", 1, "refs/heads/trunk"),
		cs(2, "js/remote-property-injection", "low", "b.ts", 1, "refs/heads/feature"),
	];
	const stripped = stripAlerts({ code });
	assert.equal(stripped.code[0].most_recent_instance.ref, "refs/heads/trunk");
	const list = buildLiveFindings({ ...stripped, defaultBranch: "trunk" });
	assert.equal(list[0].campaignCount, 1);
	assert.deepEqual(list[0].campaignRemainder, { count: 1, severity: "low" });
	const evidence = { codeql: false };
	const model = complianceModel([], list, { evidence });
	const projection = campaignProjection(model.controls, [list[0].id]);
	assert.equal(projection.lift, 3, "High deduction becomes Low, not a fully resolved group");
	assert.equal(projection.alerts, 1);
	assert.equal(projection.excluded, 1);
	assert.equal(projection.upperBound, false);
	assert.equal(model.controls.find((c) => c.id === "vuln").score, 12);
	assert.equal(projection.controls.find((c) => c.id === "vuln").score, 15, "missing evidence remains penalized");
	const offBranch = buildLiveFindings({ ...stripped, defaultBranch: "other" });
	assert.equal(campaignProjection(complianceModel([], offBranch).controls, [offBranch[0].id]).lift, 0);
	const unknown = buildLiveFindings(stripped);
	const upper = campaignProjection(complianceModel([], unknown).controls, [unknown[0].id]);
	assert.equal(upper.upperBound, true);
	assert.equal(upper.lift, 4);
	assert.equal(model.score, complianceModel([], list, { evidence }).score, "projection never mutates today");
});

test("dependency-plan projections resolve only selected dependency groups and preserve workflow/evidence deductions", () => {
	const list = [
		...findings().filter((f) => f.source === "dependabot"),
		byId(findings(), UNPINNED),
	];
	const model = complianceModel([], list);
	const ids = list.filter((f) => f.source === "dependabot").map((f) => f.id);
	const projected = remediationProjection(model.controls, [...ids, ids[0], UNPINNED], "dependencies");
	const resolved = complianceModel(ids, list);
	assert.equal(projected.score, resolved.score);
	assert.equal(projected.lift, resolved.score - model.score);
	assert.equal(projected.groups, ids.length);
	assert.equal(projected.alerts, 6);
	assert.equal(projected.excluded, 0);
	assert.equal(projected.upperBound, false);
	assert.equal(projected.controls.find((c) => c.id === "change").lift, 0);
	const saturated = complianceModel([], [...list, ...Array.from({ length: 10 }, (_, i) => ({ ...list[0], id: `dep-extra-${i}`, count: 25 }))]);
	assert.equal(remediationProjection(saturated.controls, [ids[0]], "dependencies").lift, 0,
		"a single package can leave the saturated theme at zero");
	assert.equal(campaignProjection(model.controls, ids).groups, 0, "updates are never a security campaign");
	assert.throws(() => remediationProjection(model.controls, ids, "unsupported"), /projection/);
	assert.equal(model.score, complianceModel([], list).score);
});

test("dependency rollups preserve per-package penalties across the top-14 display boundary", () => {
	for (const [count, penalty] of [[1, 1], [8, 2], [20, 3]]) {
		const critical = Array.from({ length: 14 }, (_, i) => dep(i + 1, `critical-${i}`, "critical"));
		const high = Array.from({ length: count }, (_, i) => dep(i + 15, "high-package", "high"));
		const low = dep(count + 15, "low-package", "low");
		const list = buildLiveFindings({ dependabot: [...critical, ...high, low] });
		const rest = byId(list, "dep-rest");
		assert.equal(rest.packages, 2);
		assert.equal(rest.postureDeduction, penalty + 1);
		const model = complianceModel([], list);
		const supply = model.controls.find((c) => c.id === "supply");
		assert.equal(supply.scoreDetails.alertPenalty, 14 + penalty + 1);
		assert.equal(supply.score, 20 - 14 - penalty - 1);
		assert.equal(supply.campaignFindings.find((f) => f.id === "dep-rest").deduction, penalty + 1);

		const selected = findingId("dep", "npm/critical-0");
		const projection = remediationProjection(model.controls, [selected], "dependencies");
		const refreshed = buildLiveFindings({ dependabot: [...critical.slice(1), ...high, low] });
		assert.equal(byId(refreshed, "dep-rest"), undefined, "both remaining packages become individual blips");
		const resolved = complianceModel([], refreshed);
		assert.equal(resolved.score, model.score + 1, "closing a package cannot worsen today's score");
		assert.equal(projection.lift, 1);
		assert.equal(projection.score, resolved.score, "preview agrees with a fresh alert sync");
		assert.equal(complianceModel([selected], list).score, resolved.score);

		const rollupProjection = remediationProjection(model.controls, ["dep-rest"], "dependencies");
		assert.equal(rollupProjection.score, complianceModel([], buildLiveFindings({ dependabot: critical })).score);
		assert.equal(rollupProjection.lift, penalty + 1);
		assert.equal(rollupProjection.alerts, count + 1);
		assert.equal(model.projected, complianceModel([], buildLiveFindings({ dependabot: [low] })).score,
			"Critical/High preview retains the low package even inside a mixed rollup");
	}
});

test("Critical/High preview retains every lower-severity package across mixed rollups and exported advice", () => {
	for (const highCount of [0, 14, 15, 20]) {
		const high = Array.from({ length: highCount }, (_, i) => dep(i + 1, `high-${i}`, "high"));
		const lower = Array.from({ length: 10 }, (_, i) => dep(i + 100, `medium-${i}`, "medium"));
		lower.push(dep(200, "low-package", "low"));
		const list = buildLiveFindings({ dependabot: [...high, ...lower] });
		const evidence = { "dependabot-config": false };
		const model = complianceModel([], list, { evidence });
		const refreshed = complianceModel([], buildLiveFindings({ dependabot: lower }), { evidence });
		assert.equal(model.projected, refreshed.score, `${highCount} High packages`);
		for (const control of model.controls) {
			assert.equal(control.projectedScore, refreshed.controls.find((next) => next.id === control.id).score);
		}
		const supply = model.controls.find((control) => control.id === "supply");
		assert.equal(supply.projectedScore, refreshed.controls.find((control) => control.id === "supply").score);
		assert.match(complianceOfflineAnswer("board", supply), new RegExp(`lifts it to ${supply.projectedScore}/20`));
		assert.ok(compliancePrompt("board", supply, model).includes(`${supply.projectedScore}/20 once critical and high findings are fixed`));
		assert.ok(auditBrief(model).includes(`Once critical and high findings are fixed: ${refreshed.score} / 100`));
		assert.equal(remediationProjection(model.controls, list.map((finding) => finding.id), "dependencies").score,
			complianceModel([], [], { evidence }).score, "explicit full dependency plan still resolves every selected package");
	}
	const high = Array.from({ length: 20 }, (_, i) => dep(i + 1, `high-${i}`, "high"));
	const medium = Array.from({ length: 10 }, (_, i) => dep(i + 100, `medium-${i}`, "medium"));
	const model = complianceModel([], buildLiveFindings({ dependabot: [...high, ...medium] }));
	assert.equal(model.controls.find((control) => control.id === "supply").projectedScore, 10);
});

test("dependency rollup plans identify constituent packages without tool access", () => {
	const packages = ["@acme/alpha", "beta"];
	const list = buildLiveFindings({ dependabot: packages.map((name, i) => dep(i + 1, name, "medium")) });
	assert.equal(list.length, 1);
	assert.equal(list[0].id, "dep-rest");
	const model = complianceModel([], list);
	const control = model.controls.find((control) => control.id === "supply");
	for (const name of packages) {
		assert.ok(compliancePrompt("dependencies", control, model).includes(name));
		assert.ok(complianceOfflineAnswer("dependencies", control).includes(name));
	}
	assert.match(compliancePrompt("dependencies", control, model), /Do not call any tools/);
});

test("dependency and response-evidence advice is read-only, explicit about its scope, and does not invent fixes", () => {
	const model = { ...complianceModel([], findings(), { evidence: { "security-md": false, runbook: false } }), source: "cache" };
	const supply = model.controls.find((c) => c.id === "supply");
	const selected = { ...supply, findings: [supply.findings[0]], more: 0 };
	const plan = compliancePrompt("dependencies", selected, model);
	assert.match(plan, /ONLY the selected dependency groups/);
	assert.match(plan, /NOT a GitHub Security Campaign/);
	assert.match(plan, /Do not invent fixed versions/);
	assert.match(plan, /cached GitHub metadata/);
	assert.match(plan, /do not create sessions, campaigns, issues or pull requests/);
	assert.match(complianceOfflineAnswer("dependencies", selected), /verifies no versions or fixes/);
	const incident = model.controls.find((c) => c.id === "incident");
	assert.equal(incident.title, "Incident response evidence");
	assert.equal(incident.scoreDetails.alertPenalty, 0);
	assert.equal(incident.scoreDetails.evidencePenalty, 8);
	assert.match(compliancePrompt("evidence", incident, model), /File presence does not prove response capability/);
	assert.match(complianceOfflineAnswer("evidence", incident), /tabletop/);
	assert.match(compliancePrompt("ask", incident, model, "Fix this now"), /Do not edit files/);
});

test("compliance mapping uses the corrected articles and evidence gaps", () => {
	const text = JSON.stringify(CONTROLS);
	assert.doesNotMatch(text, /DORA Art\. 10|"Art\. 10"/);
	const ids = Object.fromEntries(CONTROLS.map((control) => [control.id, control]));
	assert.deepEqual(ids.change.dora, ["Art. 9(4)(e)"]);
	assert.deepEqual(ids.incident.nis2, ["Art. 21(2)(b)", "Art. 23"]);
	assert.deepEqual(ids.incident.dora, ["Art. 17", "Art. 19"]);
	assert.ok(ids.secrets.nis2.includes("Art. 21(2)(j)"));
	const gaps = complianceModel([], findings(), { evidence: { "security-md": false, runbook: false } });
	const incident = gaps.controls.find((control) => control.id === "incident");
	assert.equal(incident.alerts, 0);
	assert.ok(incident.evidence.some((item) => item.id === "runbook" && item.status === false));
	const closed = complianceModel([], findings(), { evidence: { "security-md": true, runbook: true } });
	assert.equal(closed.controls.find((control) => control.id === "incident").score, 20);
	const ev = repoEvidence((path) => path === "SECURITY.md", { secret_scanning_push_protection: { status: "enabled" } });
	assert.equal(ev["security-md"], true);
	assert.equal(ev.runbook, false);
	assert.equal(ev["push-protection"], true);
	assert.equal(ev["validity-checks"], null);
});

test("unrecognized CodeQL workflow names leave evidence unknown without a false deduction", () => {
	for (const paths of [[], [".github/workflows/custom-security.yml"], [".github/workflows/codeql.yaml"]]) {
		const evidence = repoEvidence((path) => !path.startsWith(".github/workflows/") || paths.includes(path));
		assert.equal(evidence.codeql, null, "default setup or a custom name cannot be disproved");
		const model = complianceModel([], [], { evidence, evidenceSource: { codeql: "checkout" } });
		assert.equal(model.score, 100);
		assert.equal(model.projected, 100);
		for (const id of ["vuln", "incident"]) {
			const control = model.controls.find((c) => c.id === id);
			const codeql = control.evidence.find((item) => item.id === "codeql");
			assert.equal(codeql.status, null);
			assert.equal(codeql.source, "unknown", "a checkout lookup is not proof of missing CodeQL");
			assert.equal(control.scoreDetails.evidencePenalty, 0);
		}
		assert.doesNotMatch(auditBrief(model), /CodeQL code scanning workflow — missing|CodeQL code scanning workflow — unknown \(repo file\)/);
	}
	for (const path of [".github/workflows/codeql.yml", ".github/workflows/codeql-advanced.yml"]) {
		const evidence = repoEvidence((candidate) => candidate === path);
		assert.equal(evidence.codeql, true);
		const control = complianceModel([], [], { evidence }).controls.find((c) => c.id === "vuln");
		assert.deepEqual(control.evidence.find((item) => item.id === "codeql"), {
			id: "codeql", short: "CodeQL", label: "CodeQL code scanning workflow", status: true, source: "checkout",
		});
		assert.equal(evidence["security-md"], false, "other missing repository files remain gaps");
	}
});

test("alert links and briefs use the resolved repository and live totals", () => {
	const list = findings();
	const lodash = byId(list, LODASH);
	const sql = byId(list, SQL);
	assert.equal(alertUrl(lodash), null);
	assert.match(alertUrl(lodash, REPO), /^https:\/\/github\.com\/acme\/widgets\/security\/dependabot\?q=is%3Aopen%20package%3Alodash/);
	assert.match(alertUrl(sql, REPO), /code-scanning\?query=is%3Aopen%20rule%3Ajs%2Fsql-injection/);
	assert.match(alertUrl(byId(list, TOKEN), REPO), /\/security\/secret-scanning$/);
	assert.match(alertUrl(byId(list, "dep-rest"), REPO), /\/security\/dependabot$/);
	const model = complianceModel([], list, { totals: TOTALS, repo: REPO });
	assert.equal(model.repo, REPO);
	assert.equal(model.controls.find((c) => c.id === "vuln").alerts, 3);
	assert.equal(model.controls.find((c) => c.id === "secrets").alerts, 1);
	const brief = auditBrief(model);
	assert.match(brief, /acme\/widgets — NIS2 \/ DORA posture brief/);
	assert.match(brief, /Open code scanning alerts: 5/);
	assert.match(brief, /2026-01-01 10:00/);
	assert.equal(findBannedPhrase(brief), null);
	for (const kind of ["plan", "board", "auditor", "ask"]) {
		for (const control of model.controls) {
			const prompt = compliancePrompt(kind, control, model, "Are we ready?");
			assert.match(prompt, /Do not call any tools/);
			assert.match(prompt, /not a legal assessment/);
			assert.equal(findBannedPhrase(prompt), null);
			const offline = complianceOfflineAnswer(kind, control);
			assert.ok(offline.length > 20);
			assert.equal(findBannedPhrase(offline), null);
		}
	}
});

test("compliance page renders preview, brief, and a Copilot thread", () => {
	const state = postureState({
		preview: true,
		brief: { open: true, at: "10:42", path: "audit-brief.md" },
		labels: { plan: "Draft a 30-day remediation plan", board: "Write the board summary", auditor: "What will an auditor ask for?" },
		threads: { vuln: [{ id: "a1", kind: "plan", question: "Draft a 30-day remediation plan", status: "done", answer: "- Week 1: fix it\n- Week 2: prove it", offline: false, prompt: "Task: draft a plan <b>" }] },
	});
	const { out } = page("compliance-scoreboard", state);
	assert.match(out, /NIS2 \/ DORA posture/);
	assert.match(out, /GitHub Advanced Security/);
	assert.match(out, /with Copilot/);
	assert.match(out, /class="ghost/);
	assert.match(out, /Posture brief/);
	assert.match(out, /Next 30 days/);
	assert.match(out, /Week 1: fix it/);
	assert.match(out, /data-act="toggle_prompt"[^>]*>View prompt/);
	assert.doesNotMatch(out, /Task: draft a plan/);
	assert.match(out, /24 h|Early warning/);
	assert.match(out, /Live/);
	assert.match(out, /href="https:\/\/github\.com\/acme\/widgets\//);
	assert.doesNotMatch(out, /DORA Art\. 10/);
	assert.equal(findBannedPhrase(out), null);
});

test("compliance findings focus on campaigns instead of individual fix execution", async () => {
	const finding = (id, source, extra = {}) => ({
		id, source, title: id, severity: "high", count: 1, rule: "js/example",
		path: "src/example.js", line: 1, controlIds: ["vuln"], ...extra,
	});
	const fixtures = [
		finding("assigned-code", "code-scanning"),
		finding("live-code", "code-scanning", { copilot: { number: 12, url: "https://github.com/example/repo/security/code-scanning/12" } }),
		finding("unassigned-code", "code-scanning"),
		finding("dependency", "dependabot"),
		finding("secret", "secret-scanning"),
	];
	const state = {
		...complianceModel([], fixtures),
		source: "github",
		assigned: { "assigned-code": { number: 11, url: "https://github.com/example/repo/security/code-scanning/11" } },
		threads: {}, pending: null,
		campaigns: { draft: null, receipts: [], busy: false },
	};
	function render(current, node = null, fetch = async () => ({ ok: true })) {
		const html = renderPage("compliance-scoreboard", current);
		const script = html.split("<script>").at(-1).replace("</script>\n</body>\n</html>", "");
		const drawn = [];
		const document = {
			getElementById(name) {
				if (name === "boot") return { textContent: html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/)[1] };
				return {
					set innerHTML(value) { drawn.push(value); },
					querySelectorAll(selector) { return selector === "[data-act]" && node ? [node] : []; },
				};
			},
		};
		// eslint-disable-next-line no-new-func
		new Function("document", "EventSource", "fetch", `${script}\nselectedId = "vuln"; draw();`)(document, class {}, fetch);
		return drawn.at(-1);
	}
	let click;
	const node = {
		dataset: { act: "toggle_campaign_selection", id: "unassigned-code", control: "vuln" },
		addEventListener(type, handler) { if (type === "click") click = handler; },
	};
	const calls = [];
	const out = render(state, node, async (url, options) => {
		calls.push({ url, body: JSON.parse(options.body) });
		return { ok: true };
	});
	assert.doesNotMatch(out, /data-act="assign_copilot"|data-act="fix_locally"|data-act="assess_priority"/);
	assert.equal((out.match(/data-act="toggle_campaign_selection"/g) ?? []).length, 4);
	assert.doesNotMatch(out, /data-act="toggle_campaign_selection" data-id="dependency"/);
	assert.match(out, /Use the radar to investigate and implement fixes/);
	assert.match(out, /<details class="c-guidance"[^>]*><summary>/);
	assert.match(out, /<details class="c-evidence"/);
	for (const anchor of out.matchAll(/<a class="fr"[^>]*>([\s\S]*?)<\/a>/g)) assert.doesNotMatch(anchor[1], /<button/);
	await click();
	assert.deepEqual(calls, [], "selection must not assign Autofix, launch a session, or publish");
	const failed = render({
		...state, threads: { vuln: [{ kind: "assign", status: "done", offline: true, question: "Assign", answer: "GitHub refused the request." }] },
	});
	assert.match(failed, /GitHub API error/);
	assert.match(failed, /GitHub refused the request/);
	assert.equal(findBannedPhrase(out), null);
});

test("Medium workflow findings do not enter the Critical/High lift preview and the page explains why", () => {
	const medium = (id, rule, count) => ({
		...byId(findings(), PERMISSIONS), id, rule, count, severity: "medium", bySeverity: { critical: 0, high: 0, medium: count, low: 0 },
	});
	const list = [medium("cs-actions-a", "actions/a", 8), medium("cs-actions-b", "actions/b", 2), medium("cs-actions-c", "actions/c", 1)];
	const options = { evidence: { codeowners: false } };
	const model = complianceModel([], list, options);
	const change = model.controls.find((c) => c.id === "change");
	assert.equal(change.alerts, 11);
	assert.equal(change.score, 8);
	assert.equal(change.projectedScore, 8);
	assert.equal(complianceModel(list.map((f) => f.id), list, options).controls.find((c) => c.id === "change").score, 16);
	const { out } = page("compliance-scoreboard", { ...model, source: "github", preview: true, threads: {} }, `selectedId = "change"; draw();`);
	assert.match(out, /all 11 open alerts are Medium or Low/);
	assert.match(out, /only closes Critical and High alerts/);
	assert.match(out, /Evidence gaps are unchanged/);
	assert.doesNotMatch(out, /data-act="fix_locally"/);
});

test("compliance projection, evidence provenance and frozen brief stay honest", () => {
	const list = findings();
	const live = complianceModel([], list, { totals: TOTALS });
	const fixedAll = complianceModel(criticalHighIds(list), list, { totals: TOTALS });
	assert.equal(live.projected, fixedAll.score);
	// Unknown settings are shown as unknown and never scored as gaps.
	const unknown = complianceModel([], list, {
		evidence: { "push-protection": null },
		evidenceSource: { "push-protection": "unknown" },
	});
	const pp = unknown.controls.find((c) => c.id === "secrets").evidence.find((e) => e.id === "push-protection");
	assert.equal(pp.status, null);
	assert.equal(pp.source, "unknown");
	assert.match(auditBrief(unknown), /Secret push protection — unknown \(setting not readable\)/);
	assert.ok(live.scoring.some((r) => r.label === "Repeats"));
	assert.match(live.applicability, /oversight framework for designated critical ICT third-party providers/);
	// A brief built earlier keeps its own numbers and flags the live change.
	const state = {
		...fixedAll,
		source: "github",
		brief: { open: true, at: "10:42", path: "audit-brief.md", model: { score: 7, projected: 70, controls: live.controls, totals: live.totals, source: "github" } },
		threads: {},
		pending: null,
	};
	const { drawn } = page("compliance-scoreboard", state);
	assert.match(drawn[0], /class="big">7</);
	assert.match(drawn[0], /rebuild to update/);
});

test("copy never carries payloads or secret shapes", () => {
	const list = findings();
	assert.equal(findBannedPhrase(copyCorpus(list, REPO)), null);
	assert.equal(findBannedPhrase(auditBrief()), null);
	for (const finding of list) assert.equal(findBannedPhrase(copilotPromptForFinding(finding, REPO)), null);
	assert.equal(escapeHtml(`<b class="x">`).includes("<"), false);
	assert.equal(findBannedPhrase("token ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "ghp_");
});

test("briefs are generic, derived from the finding and safe per source", () => {
	const list = findings();
	const sql = findingBrief(byId(list, SQL));
	assert.equal(sql.filePath, "src/app.js");
	assert.match(sql.what, /js\/sql-injection/);
	assert.match(sql.where, /src\/app\.js around line 52/);
	assert.match(sql.why, /critical severity/);
	const lodash = findingBrief(byId(list, LODASH));
	assert.match(lodash.what, /3 open Dependabot alerts on the package lodash/);
	assert.match(lodash.where, /package-lock\.json/);
	assert.equal(lodash.filePath, "package-lock.json");
	const token = findingBrief(byId(list, TOKEN));
	assert.equal(token.filePath, null);
	assert.match(token.what, /never loaded/);
	const rest = findingBrief(byId(list, "dep-rest"));
	assert.match(rest.what, /2 remaining dependency alerts/);
	assert.equal(findingBrief(null).filePath, null);
	for (const finding of list) {
		assert.ok(finding.remediation.length > 20, finding.id);
		assert.equal(findBannedPhrase(finding.remediation), null, finding.id);
	}
	assert.match(byId(list, TOKEN).remediation, /revoke|rotate/i);
	assert.match(byId(list, LODASH).remediation, /lodash/);
	const form = explainPromptForFinding(byId(list, LODASH), REPO);
	assert.match(form, /closer to the center/);
	assert.match(form, /acme\/widgets/);
	assert.equal(findBannedPhrase(form), null);
});

test("radar distance is severity and briefs stay safe", () => {
	const laid = layoutFindings([
		...findings(),
		...["a", "b", "c", "d", "e"].map((x, i) => ({ ...byId(findings(), SQL), id: `crit-${x}`, severity: i % 2 ? "critical" : "high" })),
		...["a", "b", "c", "d", "e", "f"].map((x) => ({ ...byId(findings(), UNPINNED), id: `med-${x}` })),
	]);
	const distance = (finding) => Math.hypot(finding.x - 50, finding.y - 50);
	const critical = laid.filter((finding) => finding.severity === "critical");
	const high = laid.filter((finding) => finding.severity === "high");
	const medium = laid.filter((finding) => finding.severity === "medium");
	assert.ok(critical.length && high.length && medium.length);
	assert.ok(Math.max(...critical.map(distance)) < Math.min(...high.map(distance)));
	assert.ok(Math.max(...high.map(distance)) < Math.min(...medium.map(distance)));
	assert.ok(critical.every((finding) => finding.radius > 12 && finding.radius < RING_RADIUS.high - 4));
	assert.ok(high.every((finding) => finding.radius > RING_RADIUS.critical + 6 && finding.radius < RING_RADIUS.medium - 4));
	assert.ok(medium.every((finding) => finding.radius > RING_RADIUS.high + 4 && finding.radius < 46));
	const gaps = (list) => {
		const angles = list.map((f) => ((f.angle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2)).sort((a, b) => a - b);
		return angles.map((angle, index) => (index === angles.length - 1 ? angles[0] + Math.PI * 2 : angles[index + 1]) - angle);
	};
	const highGaps = gaps(high);
	assert.ok(Math.max(...highGaps) - Math.min(...highGaps) > 0.25, "high ring should not be evenly spaced");
	const mediumGaps = gaps(medium);
	assert.ok(Math.max(...mediumGaps) > Math.min(...mediumGaps) * 1.6, "outer contacts should not sit on a square");
});

test("reset is disabled while busy and clears transient selection after the shared reset event", () => {
	const state = { ...postureState(), resetEpoch: 0, resetBlocked: true };
	const html = renderPage("compliance-scoreboard", state);
	const script = html.split("<script>").at(-1).replace("</script>\n</body>\n</html>", "");
	const drawn = [];
	const field = { value: "draft", id: "reset-input" };
	let events;
	const document = {
		getElementById(name) {
			if (name === "boot") return { textContent: html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/)[1] };
			if (name === field.id) return field;
			return {
				set innerHTML(value) { drawn.push(value); },
				querySelectorAll(selector) { return selector === "input[id]" ? [field] : []; },
			};
		},
	};
	// eslint-disable-next-line no-new-func
	const getTransient = new Function("document", "EventSource",
		`${script}\nselectedId = "chosen"; openPrompts.ask = true; return () => ({selectedId, open: Object.keys(openPrompts)});`
	)(document, class { constructor() { events = this; } });
	assert.match(drawn[0], /data-act="reset_demo" disabled/);
	events.onmessage({ data: JSON.stringify({ ...state, resetEpoch: 1, resetBlocked: false }) });
	assert.deepEqual(getTransient(), { selectedId: null, open: [] });
	assert.equal(field.value, "");
	assert.match(drawn.at(-1), /data-act="reset_demo" title=/);
});

test("pages render two English canvases and a friendly empty state", () => {
	assert.deepEqual(CANVAS_IDS, ["attack-surface-radar", "compliance-scoreboard"]);
	const pages = {
		"attack-surface-radar": radarState(),
		"compliance-scoreboard": postureState(),
	};
	for (const [id, state] of Object.entries(pages)) {
		const html = renderPage(id, state);
		assert.match(html, /<html lang="en">/);
		assert.ok(html.includes(`<title>${id}</title>`));
		assert.equal(html.includes("<script>alert"), false);
		assert.equal(findBannedPhrase(html), null);
		const { drawn } = page(id, state);
		assert.ok(drawn[0].length > 40, id);
		assert.match(drawn[0].match(/<header[\s\S]*?<\/header>/)?.[0] ?? "", /data-act="reset_demo"/, id);
	}
	assert.match(page("compliance-scoreboard", pages["compliance-scoreboard"]).out, /GitHub Advanced Security/);
	assert.match(page("attack-surface-radar", pages["attack-surface-radar"]).out, /Attack surface radar/);
	const radarHtml = renderPage("attack-surface-radar", pages["attack-surface-radar"]);
	assert.match(radarHtml, /conic-gradient\(from 0deg at 50% 50%/);
	assert.match(radarHtml, /transform-origin: 50% 50%/);
	assert.match(radarHtml, /class="halo"/);
	assert.doesNotMatch(radarHtml, /M50 50 L50 5/);
	assert.match(radarHtml, />Explain<\/button>/);
	assert.match(radarHtml, /Fix locally/);
	assert.match(radarHtml, /Fix in the cloud/);
	assert.doesNotMatch(radarHtml, /Suggest a fix|How to read the radar|What could an attacker do\?/);
	assert.match(radarHtml, /Ask Copilot about this alert/);
	assert.doesNotMatch(radarHtml, /Open the file|Also in this file|Mark contained|SAY THIS|Why this distance/i);
	assert.doesNotMatch(radarHtml, /class="sweep"/);
	const withKpis = page("attack-surface-radar", radarState({
		threads: { [SQL]: [{ id: "a1", kind: "explain", question: "Explain the vuln", status: "done", answer: "**Risk**: the query.\n- Bind values", offline: false }] },
	})).out;
	assert.match(withKpis, /Quick wins/);
	assert.match(withKpis, /Top priority/);
	assert.match(withKpis, /Open secret alerts/);
	assert.match(withKpis, /upgrades may fix these/);
	assert.doesNotMatch(withKpis, /Exposed secrets|alerts closed by/);
	assert.match(withKpis, /data-tooltip=/);
	assert.match(withKpis, /Syncing…/);
	assert.match(withKpis, /Live from GitHub, synced/);
	assert.match(withKpis, /Refresh from GitHub/);
	assert.doesNotMatch(withKpis, /--accent/);
	assert.equal(findBannedPhrase(withKpis), null);
});

test("both canvases show a not-synced empty state with the failure reason", () => {
	const empty = { findings: [], totals: EMPTY_TOTALS, source: "none", repo: REPO, threads: {}, disclaimer: "Illustrative" };
	for (const id of CANVAS_IDS) {
		const idle = page(id, id === "compliance-scoreboard" ? { ...complianceModel(), ...empty } : empty).out;
		assert.match(idle, /No data yet — Sync from GitHub/, id);
		assert.match(idle, /acme\/widgets/, id);
		assert.match(idle, /Sync from GitHub<\/span>/, id);
		assert.doesNotMatch(idle, /role="alert"/, id);
		const failed = page(id, { ...empty, refreshError: "Could not sync from GitHub: gh is not authenticated." }).out;
		assert.match(failed, /role="alert"[^>]*>Could not sync from GitHub: gh is not authenticated\./, id);
		const noRepo = page(id, { ...empty, repo: null, repoError: "Could not determine the GitHub repository for this session." }).out;
		assert.match(noRepo, /Could not determine the GitHub repository/, id);
		assert.doesNotMatch(noRepo, /data-act="refresh"/, id);
		const busy = page(id, { ...empty, refreshing: true }).out;
		assert.match(busy, /Syncing from GitHub…/, id);
	}
});

test("remote URLs resolve to owner/name", () => {
	assert.equal(parseRemoteRepo("https://github.com/acme/widgets.git"), "acme/widgets");
	assert.equal(parseRemoteRepo("https://github.com/acme/widgets/"), "acme/widgets");
	assert.equal(parseRemoteRepo("https://user@github.com/acme/widgets"), "acme/widgets");
	assert.equal(parseRemoteRepo("git@github.com:acme/widgets.git"), "acme/widgets");
	assert.equal(parseRemoteRepo("ssh://git@github.com/acme/my.repo.git\n"), "acme/my.repo");
	for (const remote of ["https://gitlab.com/acme/widgets.git", "git@gitlab.com:acme/widgets.git",
		"ssh://git@github.example.com/acme/widgets.git", "https://github.com.evil.test/acme/widgets.git",
		"https://github.com@evil.test/acme/widgets.git", "https://evil.test/github.com/acme/widgets.git"]) {
		assert.equal(parseRemoteRepo(remote), null, remote);
	}
	assert.equal(parseRemoteRepo("not a url"), null);
	assert.equal(parseRemoteRepo("https://github.com/acme"), null);
	assert.equal(parseRemoteRepo(""), null);
	assert.equal(parseRemoteRepo(null), null);
});

test("radar KPIs and Copilot prompts stay short and safe", () => {
	const list = findings();
	const k = radarKpis(list, TOTALS);
	assert.equal(k.open, 12);
	assert.equal(k.criticalHigh, 7);
	assert.equal(k.quickWinBumps, 2);
	assert.equal(k.quickWinAlerts, 4);
	assert.equal(k.secrets, 1);
	const critical = byId(list, SQL);
	for (const kind of ["explain", "fix", "ask"]) {
		const prompt = radarPrompt(kind, critical, "Who can reach this?", { attached: true, repo: REPO });
		assert.equal(findBannedPhrase(prompt), null);
		assert.match(prompt, /^Attack surface radar canvas on acme\/widgets\./);
		assert.match(prompt, /src\/app\.js:52/);
		assert.match(prompt, /no code/i);
		assert.match(prompt, /Do not call any tools/);
	}
	assert.match(radarPrompt("explain", critical), /on this repository\./);
	const secretFinding = list.find((f) => f.source === "secret-scanning");
	assert.equal(radarAttachment(secretFinding, "/repo"), null);
	assert.match(radarPrompt("explain", secretFinding), /Never look up or display a secret value/);
	for (const finding of list) {
		for (const kind of ["explain", "fix"]) {
			const answer = radarOfflineAnswer(kind, finding);
			assert.ok(answer.length > 40);
			assert.equal(findBannedPhrase(answer), null);
		}
	}
});

test("contextual priority prompts permit bounded evidence reads without changing severity or inventing scores", () => {
	for (const finding of findings()) {
		const prompt = radarPrompt("assess", finding, "", { attached: true });
		assert.equal(findBannedPhrase(prompt), null);
		assert.match(prompt, /AI triage suggestion, not a CVSS score or a GitHub severity change/);
		assert.match(prompt, /Cite repository file:line evidence/);
		assert.match(prompt, /remaining occurrences were not assessed/);
		assert.match(prompt, /Do not edit files/);
		if (finding.source === "secret-scanning") {
			assert.match(prompt, /Do not call tools or read the affected file/);
			assert.doesNotMatch(prompt, /read-only inspection/);
		} else {
			assert.match(prompt, /at most six relevant files/);
			assert.match(prompt, /Do not run shell commands/);
			assert.doesNotMatch(prompt, /Do not call any tools/);
		}
	}
	assert.match(radarOfflineAnswer("assess", findings()[0]), /No AI priority was assigned/);
});

test("execution canvases link to launched sessions while the posture canvas stays campaign-focused", () => {
	const id = SQL;
	const local = { status: "launched", sessionId: "test-child", appUrl: "ghapp://sessions/test-child" };
	const pages = {
		"attack-surface-radar": radarState({ findings: layoutFindings([byId(findings(), id)]), localFixes: { [id]: local } }),
		"compliance-scoreboard": postureState({ ...complianceModel([], [byId(findings(), id)], { repo: REPO }), localFixes: { [id]: local } }),
	};
	for (const [canvasId, state] of Object.entries(pages)) {
		const { out } = page(canvasId, state);
		if (canvasId === "compliance-scoreboard") {
			assert.doesNotMatch(out, /href="ghapp:\/\/sessions\/test-child"|Open dedicated fix session/);
		} else {
			assert.match(out, /href="ghapp:\/\/sessions\/test-child"/, canvasId);
			assert.match(out, /Open dedicated fix session/, canvasId);
		}
		assert.doesNotMatch(out, /branch \+ PR in chat|Fix it in this chat|changed code in a branch/, canvasId);
	}
});

test("radar free-form requests to change code get an editing prompt on a neutral branch", () => {
	for (const q of [
		"create a pr with the fix for that vuln",
		"fix it in a branch",
		"can you fix this?",
		"corrige ça dans une branche",
		"tu peux corriger la vuln ?",
		"Please patch it and commit",
		"Commit this fix",
		"Push the current branch",
		"Could you open a pull request?",
	]) {
		assert.equal(wantsChange(q), true, q);
	}
	for (const q of [
		"How bad is this?", "Who can reach this?", "how would you fix this?", "Explain the fix direction", "",
		"Which branch contains this alert?", "What commit introduced it?", "What should I check before push?",
		"Is there a PR for this?", "Can you explain how to fix this in a branch?",
		"Please explain this commit", "Please review this PR", "Could you show the branch?",
		"Peux-tu expliquer ce commit ?", "Quelle branche contient cette alerte ?",
		"Please don't fix this; just explain the risk", "Please do not fix this",
		"Don't push this branch", "Could you avoid modifying this?",
		"Ne corrige pas ça, explique le risque", "Tu peux expliquer sans modifier ?",
		"Please discuss whether we should fix this", "Please consider a fix",
		"Maybe fix this", "Fix this if it is safe", "Please only explain the fix",
		"Make a branch protection recommendation", "Create a PR description for this alert",
		"Open the PR list for this rule", "Patch notes for this rule?",
		"Please create a branch naming recommendation", "Could you make a PR template?",
		"Can you apply the patch notes?", "Create a PR description and explain the fix",
	]) {
		assert.equal(wantsChange(q), false, q);
	}
	const critical = byId(findings(), SQL);
	const prompt = radarPrompt("change", critical, "fix it in a branch", { attached: true, repo: REPO });
	assert.equal(findBannedPhrase(prompt), null);
	assert.doesNotMatch(prompt, /Do not call any tools|do not edit files/);
	assert.match(prompt, /Never commit to the default branch/);
	assert.match(prompt, /security-radar\/sql-injection/);
	assert.match(prompt, /Request: fix it in a branch/);
	assert.match(prompt, /create_pull_request only if/);
});

test("assign to Copilot targets the shown alert in the resolved repo and keeps human assignees", () => {
	const finding = byId(findings(), PATH);
	const alerts = [
		{ number: 9, rule: { id: finding.rule }, state: "open", most_recent_instance: { location: { path: "x.js", start_line: 1 } } },
		{ number: 3, rule: { id: finding.rule }, state: "open", assignees: [{ login: "mona" }], most_recent_instance: { location: { path: finding.path, start_line: finding.line } } },
		{ number: 2, rule: { id: "js/other" }, state: "open" },
	];
	const alert = pickRadarAlert(alerts, finding);
	assert.equal(alert.number, 3);
	const req = assignCopilotRequest(alert, REPO);
	assert.equal(req.path, "repos/acme/widgets/code-scanning/alerts/3");
	assert.deepEqual(req.body.assignees, ["mona", COPILOT_ASSIGNEE]);
	assert.throws(() => assignCopilotRequest(alert, null), /not resolved/);
	assert.equal(pickRadarAlert(alerts.slice(0, 1), finding).number, 9);
	assert.equal(pickRadarAlert([], finding), null);
	assert.equal(isCopilotLogin("Copilot"), true);
	assert.equal(isCopilotLogin("copilot-swe-agent[bot]"), true);
	assert.equal(isCopilotLogin("github-agentic-autofix[bot]"), true);
	assert.equal(isCopilotLogin("mona"), false);
	assert.deepEqual(assignCopilotRequest(alert, REPO, "copilot-swe-agent[bot]").body.assignees, ["mona", "copilot-swe-agent[bot]"]);
	const live = buildLiveFindings(stripAlerts({ code: [{
		number: 3, html_url: "https://github.com/x/y/security/code-scanning/3", rule: { id: finding.rule },
		assignees: [{ login: COPILOT_ASSIGNEE }], most_recent_instance: { location: { path: finding.path, start_line: finding.line } },
	}] }));
	assert.equal(live[0].htmlUrl, "https://github.com/x/y/security/code-scanning/3");
	assert.equal(live[0].copilot.number, 3);
	assert.equal(radarFindingUrl(live[0], REPO), live[0].htmlUrl);
	assert.match(radarFindingUrl(finding, REPO), /^https:\/\/github\.com\/acme\/widgets\/security\/code-scanning\?query=/);
	assert.equal(canAssignCopilot(finding), true);
	assert.equal(canAssignCopilot(byId(findings(), LODASH)), false);
	assert.equal(canAssignCopilot(byId(findings(), TOKEN)), false);
});

test("radar offline answers are useful for every ask kind", () => {
	const finding = byId(findings(), SQL);
	for (const kind of ["explain", "fix", "ask", "change"]) {
		const answer = radarOfflineAnswer(kind, finding);
		assert.ok(answer.length > 40, kind);
		assert.equal(findBannedPhrase(answer), null);
	}
	assert.match(radarOfflineAnswer("ask", finding), /summary from the alert data/);
	assert.ok(radarOfflineAnswer("ask", finding).includes(finding.remediation));
	assert.ok(radarOfflineAnswer("fix", finding).includes(finding.remediation));
});

test("radar reshuffle moves bearings but keeps every finding in its band", () => {
	const list = [
		...findings(),
		...["a", "b", "c", "d"].map((x) => ({ ...byId(findings(), PATH), id: `high-${x}` })),
		...["a", "b", "c"].map((x) => ({ ...byId(findings(), UNPINNED), id: `med-${x}` })),
	];
	const base = layoutFindings(list);
	const band = { critical: [14.2, 20.8], high: [24.4, 36.6], medium: [40.6, 44.2], low: [45, 46.2] };
	let moved = 0;
	for (let seed = 1; seed <= 40; seed += 1) {
		const laid = layoutFindings(list, seed * 7919);
		const index = new Map(laid.map((f) => [f.id, f]));
		for (const f of base) {
			const g = index.get(f.id);
			const [lo, hi] = band[g.severity];
			assert.ok(g.radius >= lo - 1e-9 && g.radius <= hi + 1e-9, f.id);
			if (Math.abs(g.angle - f.angle) > 0.2) moved += 1;
		}
		const d = (f) => Math.hypot(f.x - 50, f.y - 50);
		const sev = (name) => laid.filter((f) => f.severity === name).map(d);
		assert.ok(Math.max(...sev("critical")) < Math.min(...sev("high")));
		assert.ok(Math.max(...sev("high")) < Math.min(...sev("medium")));
		for (let i = 0; i < laid.length; i += 1)
			for (let j = i + 1; j < laid.length; j += 1)
				assert.ok(Math.hypot(laid[i].x - laid[j].x, laid[i].y - laid[j].y) > 6, `${seed}: ${laid[i].id}/${laid[j].id}`);
	}
	assert.ok(moved > base.length * 20);
});

test("radar only replays the arrival when a sync brings a new layout", () => {
	const base = radarState({
		findings: layoutFindings([{ ...byId(findings(), PATH), count: 30 }]),
		layoutSeed: 1,
	});
	const html = renderPage("attack-surface-radar", base);
	const script = html.split("<script>").at(-1).replace("</script>\n</body>\n</html>", "");
	const frames = [];
	let stream;
	const document = {
		getElementById(name) {
			if (name === "boot") return { textContent: html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/)[1] };
			return { set innerHTML(value) { frames.push(value); }, querySelectorAll() { return []; } };
		},
	};
	class EventSource { constructor() { stream = this; } }
	const clock = { t: 0, now() { return this.t; } };
	// eslint-disable-next-line no-new-func
	new Function("document", "EventSource", "JSON", "Math", "performance", script)(document, EventSource, JSON, Math, clock);
	const push = (patch) => {
		clock.t += 5000;
		stream.onmessage({ data: JSON.stringify({ ...base, ...patch }) });
	};
	const arrives = () => /class="blip[^"]*\barrive\b/.test(frames.at(-1));
	assert.ok(arrives(), "first paint flies in");
	assert.match(frames.at(-1), /width:28px/, "30 alerts draws the biggest dot");
	push({ refreshing: true });
	assert.equal(arrives(), false, "no arrival while syncing");
	push({ refreshing: false, source: "cache", refreshError: "GitHub is unreachable." });
	assert.equal(arrives(), false, "failed sync keeps the dots still");
	assert.match(frames.at(-1), /class="src cache"/, "failed sync drops the LIVE pill");
	push({ refreshing: false, layoutSeed: 2 });
	assert.ok(arrives(), "successful sync flies the dots in again");
});
