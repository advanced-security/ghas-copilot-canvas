import assert from "node:assert/strict";
import test from "node:test";
import { CAMPAIGN_REFRESH_MS, campaignFields, campaignScope, createCampaignService, scheduleCampaignProgress } from "./campaigns.mjs";
import { buildLiveFindings, complianceModel, findingId, remediationProjection } from "./logic.mjs";
import { renderPage } from "./pages.mjs";

const repo = "acme/widgets";
const code = (number, ref = "refs/heads/main", state = "open") => ({
	number, state, rule: { id: "js/test", description: "Test rule" },
	most_recent_instance: { ref, location: { path: "api/src/test.ts", start_line: 1 } },
});
const advisory = (number, name, severity, manifest = "package-lock.json") => ({
	number, dependency: { package: { ecosystem: "npm", name }, manifest_path: manifest }, security_advisory: { severity },
});
const fixtureFindings = () => buildLiveFindings({ defaultBranch: "main", code: [
	{ number: 1, rule: { id: "actions/unpinned-tag", description: "Unpinned action", security_severity_level: "medium" },
		most_recent_instance: { ref: "refs/heads/main", location: { path: ".github/workflows/ci.yml", start_line: 12 } } },
	{ number: 2, rule: { id: "js/sql-injection", description: "SQL injection", security_severity_level: "high" },
		most_recent_instance: { ref: "refs/heads/main", location: { path: "src/app.js", start_line: 30 } } },
], dependabot: [advisory(1, "lodash", "high"), advisory(2, "lodash", "high"), advisory(3, "express", "high"),
	...["axios", "minimist", "qs", "semver", "tar", "ws", "yaml"].map((name, i) => advisory(10 + i, name, "high"))] });
const groups = [
	{ id: "cs-test", source: "code-scanning", title: "Test rule", rule: "js/test", count: 2 },
	{ id: "sec-test", source: "secret-scanning", title: "Secret type", rule: "slugged-type", campaignSelector: "provider_type", count: 1 },
	{ id: "dep-test", source: "dependabot", title: "Dependency", rule: "npm/test", count: 7 },
];
const fields = { name: "Fix alerts", description: "Security remediation", dueDate: "2030-02-28", manager: "mona" };
const time = Date.parse("2030-01-01T12:00:00Z");

function harness(options = {}) {
	const data = options.data ?? { draft: null, receipts: [] };
	const requests = [];
	const saved = [];
	const logs = [];
	let alerts = [code(1), code(2)];
	let response = { number: 7, name: fields.name, state: "open", ends_at: "2030-02-28T23:59:59Z", alert_stats: { open_count: 2, closed_count: 0, in_progress_count: 1 } };
	const service = createCampaignService({
		data, now: () => time,
		context: options.context ?? (async () => ({ repo, repositoryId: 42, branch: "main", organization: true, manager: "mona" })),
		list: options.list ?? (async () => alerts),
		api: options.api ?? (async (method, path, body) => {
			requests.push({ method, path, body });
			return response;
		}),
		persist: options.persist ?? (async (value) => saved.push(structuredClone(value))),
		broadcast() {}, log(message) { logs.push(message); },
	});
	return { data, service, requests, saved, logs, setAlerts(value) { alerts = value; }, setResponse(value) { response = value; } };
}

async function prepared(h) {
	const d = await h.service.prepare(groups, "code", "Vulnerability handling");
	return h.service.review({ id: d.id, ...fields });
}

const creationInput = (draft, extra = {}) => ({
	id: draft.id, revision: draft.revision, ids: ["cs-test"], confirm: true, ...fields, ...extra,
});

test("direct creation uses the authenticated manager, saves intent and creates exactly one linked campaign", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	assert.equal(d.manager, "mona");
	const receipt = await h.service.create(creationInput(d, { manager: "not-the-current-user" }));
	assert.equal(receipt.status, "published");
	assert.match(receipt.campaign.url, /\/security\/campaigns\/7$/);
	assert.deepEqual(h.requests[0].body.managers, ["mona"]);
	assert.deepEqual(h.requests[0].body.code_scanning_alerts, [{ repository_id: 42, alert_numbers: [1, 2] }]);
	assert.ok(h.saved.some((saved) => saved.receipts[0]?.status === "publishing"));
	assert.equal(h.service.state().draft, null);
	await assert.rejects(h.service.create(creationInput(d)), /confirm creation/);
	assert.equal(h.requests.filter((r) => r.method === "POST").length, 1);
	assert.equal(h.requests[1].method, "GET");
});

test("direct creation validates confirmation, revision, selected groups and form before any publication", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	for (const override of [{ confirm: false }, { revision: "stale" }, { ids: [] }, { ids: ["cs-test", "cs-test"] },
		{ name: "" }, { dueDate: "2030-02-30" }]) {
		await assert.rejects(h.service.create(creationInput(d, override)));
	}
	assert.equal(h.requests.length, 0);
	assert.equal(h.service.state().draft.revision, d.revision);
});

test("direct creation revalidates changing alert scope and requires a new explicit submission", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	h.setAlerts([code(1), code(2), code(3)]);
	await assert.rejects(h.service.create(creationInput(d)), /alert selection changed/);
	assert.equal(h.requests.length, 0);
	const updated = h.service.state().draft;
	assert.deepEqual(updated.numbers, [1, 2, 3]);
	await assert.rejects(h.service.create(creationInput(d)), /confirm creation/);
	await h.service.create(creationInput(updated));
	assert.deepEqual(h.requests[0].body.code_scanning_alerts[0].alert_numbers, [1, 2, 3]);
});

test("direct creation surfaces authentication changes and missing authenticated manager without publication", async () => {
	let manager = "mona";
	const h = harness({ context: async () => ({ repo, repositoryId: 42, branch: "main", organization: true, manager }) });
	const d = await h.service.prepare(groups, "code", "Test");
	manager = undefined;
	await assert.rejects(h.service.create(creationInput(d)), /manager/);
	manager = "next-user";
	await assert.rejects(h.service.create(creationInput(d)), /account changed/);
	assert.equal(h.requests.length, 0);
	assert.equal(h.service.state().draft.manager, "next-user");
	await h.service.create(creationInput(h.service.state().draft));
	assert.deepEqual(h.requests[0].body.managers, ["next-user"]);
});

test("direct creation protects ambiguous publication and never automatically retries", async () => {
	let posts = 0;
	const h = harness({ api: async () => { posts++; throw new Error("Network timeout"); } });
	const d = await h.service.prepare(groups, "code", "Test");
	await assert.rejects(h.service.create(creationInput(d)), /could not be confirmed/);
	assert.equal(h.service.state().publicationBlocked, true);
	await assert.rejects(h.service.create(creationInput(h.service.state().draft)), /unconfirmed/);
	await h.service.reset();
	assert.equal(h.service.state().draft, null);
	assert.equal(h.service.state().receipts[0].status, "unknown");
	assert.equal(posts, 1);
});

test("direct creation holds the campaign lock through the complete transaction", async () => {
	let begin;
	let finish;
	const started = new Promise((resolve) => { begin = resolve; });
	const gate = new Promise((resolve) => { finish = resolve; });
	const h = harness({ api: async () => { begin(); await gate; return { number: 8 }; } });
	const d = await h.service.prepare(groups, "code", "Test");
	const submitting = h.service.create(creationInput(d));
	await started;
	await assert.rejects(h.service.reset(), /operation to finish/);
	await assert.rejects(h.service.create(creationInput(d)), /operation to finish/);
	finish();
	assert.equal((await submitting).status, "published");
});

test("direct creation cannot send a request when reviewed fields cannot be saved", async () => {
	const h = harness({ persist: async (data) => { if (data.draft?.status === "reviewed") throw new Error("Disk full"); } });
	const d = await h.service.prepare(groups, "code", "Test");
	await assert.rejects(h.service.create(creationInput(d)), /Disk full/);
	assert.equal(h.requests.length, 0);
	assert.equal(h.service.state().draft.revision, d.revision);
});

test("direct creation restores the form if an authenticated-manager change cannot be saved", async () => {
	let manager = "mona";
	let rejectSave = false;
	const h = harness({
		context: async () => ({ repo, repositoryId: 42, branch: "main", organization: true, manager }),
		persist: async () => { if (rejectSave) throw new Error("Disk full"); },
	});
	const d = await h.service.prepare(groups, "code", "Test");
	manager = "next-user";
	rejectSave = true;
	await assert.rejects(h.service.create(creationInput(d)), /Disk full/);
	assert.equal(h.service.state().draft.manager, "mona");
	assert.equal(h.service.state().draft.revision, d.revision);
	assert.equal(h.requests.length, 0);
});

test("campaign selection uses exact open default-branch code numbers, keeps types separate and excludes dependencies", () => {
	const scope = campaignScope(groups, "code", [code(2), code(1), code(2), code(3, "refs/heads/feature"), code(4, "refs/heads/main", "dismissed")], "main");
	assert.deepEqual(scope.numbers, [1, 2]);
	assert.deepEqual(scope.excludedGroups.map((g) => g.source), ["secret-scanning", "dependabot"]);
	const secrets = campaignScope(groups, "secrets", [
		{ number: 3, state: "open", secret_type: "provider_type", secret: "NEVER-COPY-ME" },
		{ number: 4, state: "resolved", secret_type: "provider_type" },
	], "main");
	assert.deepEqual(secrets.numbers, [3]);
	assert.doesNotMatch(JSON.stringify(secrets), /NEVER-COPY-ME/);
	assert.throws(() => campaignScope(groups, "dependencies", [], "main"), /code or secrets/);
	assert.throws(() => campaignScope(groups, "code", [code(1, "refs/heads/feature")], "main"), /No eligible/);
	assert.throws(() => campaignScope(groups, "code", Array.from({ length: 1001 }, (_, i) => code(i + 1)), "main"), /at most 1000/);
	assert.throws(() => campaignScope(groups, "code", [code("1")], "main"), /invalid alert number/);
	const findings = buildLiveFindings({ secrets: [{ number: 1, secret_type: "provider_type" }] });
	assert.equal(findings[0].campaignSelector, "provider_type");
});

test("campaign fields enforce exact API limits, future dates and manager syntax", () => {
	assert.equal(campaignFields(fields, time).endsAt, "2030-02-28T23:59:59Z");
	for (const patch of [{ name: "" }, { name: "x".repeat(51) }, { description: "x".repeat(196) }, { description: "" },
		{ dueDate: "2030-02-30" }, { dueDate: "2029-01-01" }, { manager: "" }, { manager: "../bad" }]) {
		assert.throws(() => campaignFields({ ...fields, ...patch }, time));
	}
});

test("prepare and review are durable local-only; explicit exact confirmation publishes correct payload", async () => {
	const h = harness();
	const d = await prepared(h);
	assert.equal(h.requests.length, 0);
	assert.equal(h.saved.at(-1).draft.status, "reviewed");
	assert.deepEqual(d.numbers, [1, 2]);
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision }), /explicitly confirm/);
	await assert.rejects(h.service.publish({ id: d.id, revision: "stale", confirm: true }), /Review/);
	const result = await h.service.publish({ id: d.id, revision: d.revision, confirm: true });
	assert.equal(result.status, "published");
	assert.equal(h.data.draft, null);
	assert.deepEqual(h.requests[0].body.code_scanning_alerts, [{ repository_id: 42, alert_numbers: [1, 2] }]);
	assert.deepEqual(h.requests[0].body.managers, ["mona"]);
	assert.equal(h.requests[0].body.generate_issues, false);
	assert.ok(h.requests[0].body.description.length <= 255);
	assert.match(h.requests[0].body.description, /\[canvas:/);
	assert.match(result.campaign.url, /\/orgs\/acme\/security\/campaigns\/7$/);
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /Review/);
	await h.service.reset();
	assert.equal(h.data.receipts[0].campaign.number, 7);
	h.setResponse({ number: 7, state: "closed", alert_stats: { open_count: 0, closed_count: 2, in_progress_count: 0 } });
	await h.service.refresh();
	assert.equal(h.data.receipts[0].campaign.stats.closed_count, 2);
	assert.equal(h.requests.filter((r) => r.method === "POST").length, 1);
});

test("scope shrink and growth invalidate review; branch/repo changes and personal repos reject publication", async () => {
	for (const alerts of [[code(1)], [code(1), code(2), code(3)]]) {
		const h = harness();
		const d = await prepared(h);
		h.setAlerts(alerts);
		await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /selection changed/);
		assert.equal(h.data.draft.status, "draft");
		assert.notEqual(h.data.draft.revision, d.revision);
		assert.equal(h.requests.length, 0);
	}
	const personal = harness({ context: async () => ({ organization: false }) });
	await assert.rejects(personal.service.prepare(groups, "code", "Test"), /organization-owned/);
	let branch = "main";
	const h = harness({ context: async () => ({ repo, repositoryId: 42, branch, organization: true }) });
	const d = await prepared(h);
	branch = "renamed";
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /default branch changed/);
	assert.equal(h.requests.length, 0);
});

test("secret preparation never publishes through an unspecified API schema or copies secret values", async () => {
	const h = harness({ list: async () => [{ number: 3, state: "open", secret_type: "provider_type", secret: "NEVER-COPY-ME" }] });
	const d = await h.service.prepare(groups, "secrets", "Credentials");
	assert.deepEqual(d.numbers, [3]);
	await assert.rejects(h.service.review({ id: d.id, ...fields }), /Finalize secret campaigns/);
	await assert.rejects(h.service.publish({ id: d.id, confirm: true }), /Review/);
	assert.equal(h.requests.length, 0);
	assert.doesNotMatch(JSON.stringify(h.data), /NEVER-COPY-ME/);
});

test("publication is globally serialized, Reset blocks while busy and intent persists before POST", async () => {
	let release;
	const gate = new Promise((resolve) => { release = resolve; });
	let h;
	h = harness({ api: async (method) => {
		if (method === "GET") return { number: 8, alert_stats: { open_count: 2, closed_count: 0, in_progress_count: 0 } };
		assert.equal(h.saved.at(-1).receipts[0].status, "publishing");
		await gate;
		return { number: 8 };
	} });
	const d = await prepared(h);
	const publishing = h.service.publish({ id: d.id, revision: d.revision, confirm: true });
	await new Promise((resolve) => setImmediate(resolve));
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /operation to finish/);
	await assert.rejects(h.service.prepare(groups, "code", "Other"), /operation to finish/);
	await assert.rejects(h.service.reset(), /operation to finish/);
	release();
	assert.equal((await publishing).status, "published");
});

test("timeouts remain protected across Reset, reconcile by unique marker and never retry automatically", async () => {
	const h = harness({ api: async () => { throw new Error("timeout"); } });
	const d = await prepared(h);
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /could not be confirmed/);
	assert.equal(h.data.receipts[0].status, "unknown");
	const persisted = structuredClone(h.saved.at(-1));
	await h.service.reset();
	assert.equal(h.data.receipts[0].status, "unknown");
	await assert.rejects(h.service.prepare(groups, "code", "New"), /unconfirmed/);
	const resumed = harness({ data: persisted, list: async () => [{ number: 99, description: `Security remediation\n${persisted.receipts[0].marker}`,
		alert_stats: { open_count: 2, closed_count: 0, in_progress_count: 0 } }] });
	await resumed.service.refresh();
	assert.equal(resumed.data.receipts[0].status, "published");
	assert.equal(resumed.data.receipts[0].campaign.number, 99);
	assert.equal(resumed.requests.length, 0);
	assert.equal(resumed.data.draft, null);
});

test("unknown publication can only be released by explicit user verification, while confirmed 403 can be corrected", async () => {
	const h = harness({ api: async () => { throw new Error("timeout"); }, list: async (path) => path.includes("/campaigns") ? [] : [code(1), code(2)] });
	const d = await prepared(h);
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }));
	await assert.rejects(h.service.refresh(), /remains unconfirmed/);
	await assert.rejects(h.service.acknowledgeAbsent({ id: d.id }), /Explicitly confirm/);
	await h.service.acknowledgeAbsent({ id: d.id, confirm: true });
	assert.equal(h.data.receipts[0].status, "abandoned");
	await h.service.prepare(groups, "code", "New");
	const denied = harness({ api: async () => { throw new Error("GitHub HTTP 403"); } });
	const x = await prepared(denied);
	await assert.rejects(denied.service.publish({ id: x.id, revision: x.revision, confirm: true }), /rejected publication/);
	assert.equal(denied.data.receipts[0].status, "failed");
	assert.equal(denied.service.state().publicationBlocked, false);
	await denied.service.edit({ id: x.id });
	assert.equal(denied.data.draft.status, "draft");
});

test("absence acknowledgment targets the unknown retry receipt rather than the earlier failed publication", async () => {
	let attempts = 0;
	const h = harness({ api: async () => {
		throw new Error(++attempts === 1 ? "GitHub HTTP 403" : "timeout");
	} });
	const d = await prepared(h);
	const input = { id: d.id, revision: d.revision, confirm: true };
	await assert.rejects(h.service.publish(input), /rejected publication/);
	assert.equal(h.data.receipts[0].status, "failed");
	await assert.rejects(h.service.publish(input), /could not be confirmed/);
	assert.deepEqual(h.data.receipts.map((receipt) => [receipt.id, receipt.status]), [[d.id, "failed"], [d.id, "unknown"]]);
	assert.equal(h.service.state().publicationBlocked, true);
	await assert.rejects(h.service.acknowledgeAbsent({ id: d.id, confirm: false }), /Explicitly confirm/);
	await h.service.acknowledgeAbsent({ id: d.id, confirm: true });
	assert.deepEqual(h.data.receipts.map((receipt) => receipt.status), ["failed", "abandoned"]);
	assert.equal(h.service.state().publicationBlocked, false);
	assert.equal(attempts, 2, "acknowledgment must not retry publication");
	await assert.rejects(h.service.acknowledgeAbsent({ id: d.id, confirm: true }), /Explicitly confirm/);
});

test("persistence failures prevent POST or preserve intent for reconciliation after accepted POST", async () => {
	let rejectSaving = false;
	let calls = 0;
	const h = harness({ persist: async () => { if (rejectSaving) throw new Error("disk full"); }, api: async () => { calls++; return { number: 7 }; } });
	const d = await prepared(h);
	rejectSaving = true;
	await assert.rejects(h.service.publish({ id: d.id, revision: d.revision, confirm: true }), /no request sent/);
	assert.equal(calls, 0);
	assert.equal(h.data.receipts.length, 0);
	let saves = 0;
	const accepted = harness({ persist: async () => { if (++saves === 4) throw new Error("disk full"); } });
	const x = await prepared(accepted);
	await assert.rejects(accepted.service.publish({ id: x.id, revision: x.revision, confirm: true }), /was published/);
	assert.equal(accepted.data.receipts[0].status, "published");
	await assert.rejects(accepted.service.publish({ id: x.id, revision: x.revision, confirm: true }));
	assert.equal(accepted.requests.length, 1);
});

test("shared Reset restores its campaign preparation if local-session ledger reset fails", async () => {
	const h = harness();
	const d = await prepared(h);
	await assert.rejects(h.service.reset(async () => { throw new Error("local ledger unavailable"); }), /local ledger unavailable/);
	assert.equal(h.data.draft.id, d.id);
	assert.equal(h.saved.at(-1).draft.id, d.id);
	assert.equal(h.service.busy, false);
});

test("creation fetches real progress immediately even when POST omits alert statistics", async () => {
	const requests = [];
	let h;
	h = harness({ api: async (method, path) => {
		requests.push({ method, path });
		if (method === "POST") return { number: 7, state: "open" };
		assert.equal(h.saved.at(-1).receipts[0].status, "published", "persist the successful creation before refreshing progress");
		return { number: 7, state: "open", alert_stats: { open_count: 2, closed_count: 0, in_progress_count: 1 } };
	} });
	const d = await h.service.prepare(groups, "code", "Test");
	const receipt = await h.service.create(creationInput(d));
	assert.deepEqual(requests.map((r) => r.method), ["POST", "GET"]);
	assert.equal(requests[1].path, "orgs/acme/campaigns/7");
	assert.equal(receipt.campaign.stats.open_count, 2);
	assert.equal(h.service.state().refreshedAt, new Date(time).toISOString());
	assert.equal(h.saved.at(-1).receipts[0].campaign.stats.in_progress_count, 1);
});

test("failed initial progress fetch never changes successful publication into failure or retries POST", async () => {
	const methods = [];
	let fail = true;
	const h = harness({ api: async (method) => {
		methods.push(method);
		if (method === "POST") return { number: 7 };
		if (fail) throw new Error("HTTP 503");
		return { number: 7, alert_stats: { open_count: 2, closed_count: 0, in_progress_count: 0 } };
	} });
	const d = await h.service.prepare(groups, "code", "Test");
	const receipt = await h.service.create(creationInput(d));
	assert.equal(receipt.status, "published");
	assert.equal(h.service.state().publicationBlocked, false);
	assert.equal(h.service.state().draft, null);
	assert.match(receipt.progressError, /was created.*HTTP 503/);
	assert.match(h.service.state().error, /progress could not be refreshed/);
	assert.equal(h.logs.length, 1);
	await assert.rejects(h.service.create(creationInput(d)));
	fail = false;
	await h.service.refresh();
	assert.deepEqual(methods, ["POST", "GET", "GET"]);
	assert.equal(receipt.progressError, undefined);
	assert.equal(h.service.state().error, null);
});

test("missing progress is reported honestly rather than fabricated as zero closed alerts", async () => {
	const h = harness();
	h.setResponse({ number: 7 });
	const d = await h.service.prepare(groups, "code", "Test");
	const receipt = await h.service.create(creationInput(d));
	assert.equal(receipt.status, "published");
	assert.equal(receipt.campaign.stats, null);
	assert.match(receipt.progressError, /has not returned campaign progress/);
	const r = renderer("attack-surface-radar", { findings: [], totals: {}, source: "github", campaigns: h.service.state() });
	assert.match(r.draws[0], /Progress pending from GitHub/);
	assert.doesNotMatch(r.draws[0], /Progress unavailable|0 alerts closed/);
});

test("a failed campaign refresh does not prevent other campaigns from updating or erase their last known statistics", async () => {
	const stats = { open_count: 2, closed_count: 0, in_progress_count: 0 };
	const h = harness({ data: { draft: null, receipts: [
		{ id: "first", repo, status: "published", campaign: { number: 7, stats } },
		{ id: "second", repo, status: "published", campaign: { number: 8, stats } },
	] }, api: async (method, path) => {
		assert.equal(method, "GET");
		if (path.endsWith("/7")) throw new Error("Campaign #7: HTTP 403");
		return { number: 8, alert_stats: { open_count: 0, closed_count: 2, in_progress_count: 0 } };
	} });
	await assert.rejects(h.service.refresh(), /Campaign #7: HTTP 403/);
	assert.equal(h.saved.at(-1).receipts[0].campaign.stats.open_count, 2);
	assert.equal(h.saved.at(-1).receipts[1].campaign.stats.closed_count, 2);
	assert.match(h.service.state().receipts[0].progressError, /HTTP 403/);
});

test("progress polling runs every five minutes, skips busy operations, reports errors and stops on close", async () => {
	let tick;
	let cancelled;
	let allowed = false;
	let release;
	let began;
	let reads = 0;
	const gate = new Promise((resolve) => { release = resolve; });
	const started = new Promise((resolve) => { began = resolve; });
	const errors = [];
	const h = harness({ data: { draft: null, receipts: [{ id: "done", repo, status: "published", campaign: { number: 7 } }] },
		api: async () => { reads++; began(); await gate; throw new Error("Progress API unavailable"); } });
	const timer = { unref() {} };
	const stop = scheduleCampaignProgress(h.service, {
		canRefresh: () => allowed,
		onError: (cause) => errors.push(cause.message),
		schedule: (callback, delay) => { tick = callback; assert.equal(delay, 300000); assert.equal(delay, CAMPAIGN_REFRESH_MS); return timer; },
		cancel: (handle) => { cancelled = handle; },
	});
	await tick();
	assert.equal(reads, 0);
	allowed = true;
	const refreshing = tick();
	await started;
	await tick();
	assert.equal(reads, 1, "do not overlap an active refresh");
	release();
	await refreshing;
	assert.deepEqual(errors, ["Progress API unavailable"]);
	assert.equal(h.service.state().error, "Progress API unavailable");
	await h.service.reset(undefined, { forgetCampaigns: true });
	await tick();
	assert.equal(reads, 1, "Reset's forgotten campaigns must not return on the next polling tick");
	stop();
	assert.equal(cancelled, timer);
});

test("Reset persistently forgets known campaigns without any GitHub write while discard retains them", async () => {
	const h = harness();
	const d = await prepared(h);
	await h.service.publish({ id: d.id, revision: d.revision, confirm: true });
	await h.service.reset();
	assert.equal(h.service.state().receipts.length, 1);
	const requests = h.requests.length;
	await h.service.reset(undefined, { forgetCampaigns: true });
	assert.deepEqual(h.service.state().receipts, []);
	assert.deepEqual(h.saved.at(-1).receipts, []);
	assert.equal(h.requests.length, requests);
	assert.deepEqual(harness({ data: structuredClone(h.saved.at(-1)) }).service.state().receipts, []);
});

test("Reset keeps ambiguous-publication protection and rolls back forgotten campaigns on persistence failure", async () => {
	const unknown = harness({ data: { draft: { id: "form" }, receipts: [
		{ id: "known", repo, status: "published", campaign: { number: 7 } }, { id: "uncertain", repo, status: "unknown" },
	] } });
	await unknown.service.reset(undefined, { forgetCampaigns: true });
	assert.equal(unknown.service.state().receipts.length, 1);
	assert.equal(unknown.service.state().publicationBlocked, true);
	await assert.rejects(unknown.service.prepare(groups, "code", "Test"), /unconfirmed/);
	for (const failure of ["persist", "local-ledger"]) {
		const data = { draft: { id: "form" }, receipts: [{ id: "known", repo, status: "published", campaign: { number: 7 } }] };
		const h = harness({ data, persist: async () => { if (failure === "persist") throw new Error("Disk full"); } });
		await assert.rejects(h.service.reset(async () => { if (failure === "local-ledger") throw new Error("Local ledger failed"); },
			{ forgetCampaigns: true }));
		assert.equal(h.service.state().draft.id, "form");
		assert.equal(h.service.state().receipts[0].id, "known");
	}
});

function renderer(canvasId, model, elements = [], fields = {}, checks = {}, preserveInputs = false, collections = {}, fetchImpl) {
	const html = renderPage(canvasId, model);
	const script = html.split("<script>").at(-1).replace("</script>\n</body>\n</html>", "");
	const draws = [];
	const payloads = [];
	const root = {
		set innerHTML(value) {
			draws.push(value);
			if (preserveInputs) for (const field of Object.values(fields)) field.value = "server-rendered value";
			for (const disclosure of collections["details[data-disclosure]"] ?? []) {
				const tag = value.match(new RegExp('<details[^>]*data-disclosure="' + disclosure.dataset.disclosure + '"[^>]*>'));
				disclosure.open = Boolean(tag && /\sopen(?:\s|>)/.test(tag[0]));
			}
		},
		querySelectorAll(selector) {
			if (selector === "[data-act]") return elements;
			if (selector === "input[id]" && preserveInputs) return Object.entries(fields).map(([id, field]) => Object.assign(field, { id }));
			return collections[selector] ?? [];
		},
		querySelector(selector) { return checks[selector] ?? null; },
	};
	const document = {
		getElementById(id) {
			if (id === "boot") return { textContent: html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/)[1] };
			return fields[id] ?? root;
		},
	};
	let events;
	const result = new Function("document", "EventSource", "fetch", "window",
		`${script}\nreturn { select(id) { campaignSelection.add(id); draw(); }, state() { return state; } };`)(
		document, class { constructor() { events = this; } },
		async (url, request) => {
			const payload = JSON.parse(request.body);
			payloads.push(payload);
			return fetchImpl ? fetchImpl(payload) : { ok: true };
		}, { innerWidth: 1000, innerHeight: 700 });
	return { draws, payloads, result, push(next) { events.onmessage({ data: JSON.stringify(next) }); } };
}

function element(dataset) {
	const handlers = {};
	return { dataset, handlers, classList: { contains() { return false; } }, addEventListener(name, fn) { handlers[name] = fn; } };
}

test("dependency planning previews all packages, sends only selected updates, and does not publish", async () => {
	const findings = fixtureFindings().map((f) => ({ ...f, url: "https://github.com/acme/widgets/security/dependabot", where: f.path }));
	const dependencies = findings.filter((f) => f.source === "dependabot");
	const mapped = findings.filter((f) => f.controlIds.includes("supply"));
	const model = { ...complianceModel([], findings), source: "github", preview: true,
		campaignThemes: { supply: mapped }, campaigns: { draft: null, receipts: [] }, resetEpoch: 0 };
	const select = element({ act: "select", id: "supply" });
	const all = element({ act: "select_dependency_theme", control: "supply" });
	const draft = element({ act: "draft_dependency_plan", control: "supply" });
	const clear = element({ act: "clear_dependency_selection", control: "supply" });
	const bad = element({ act: "toggle_dependency_selection", control: "supply", id: findingId("cs", "actions/unpinned-tag") });
	const r = renderer("compliance-scoreboard", model, [select, all, draft, clear, bad]);
	await select.handlers.click();
	let out = r.draws.at(-1);
	assert.match(out, /Dependabot upgrade plan/);
	assert.match(out, /not a Security Campaign/);
	assert.match(out, /title="Open Dependabot alerts"/);
	assert.match(out, /Preview all includes these too/);
	assert.doesNotMatch(out, /data-act="toggle_campaign_selection" data-id="dep-/);
	await bad.handlers.click();
	await draft.handlers.click();
	assert.equal(r.payloads.length, 0, "empty or unsupported update scope must send no request");
	await all.handlers.click();
	out = r.draws.at(-1);
	const projection = remediationProjection(model.controls, dependencies.map((f) => f.id), "dependencies");
	assert.match(out, new RegExp('Upgrade plan lift</span><div class="kpi-value"><span class="up">\\+' + projection.lift));
	assert.match(out, /selected updates/);
	assert.match(out, /data-act="toggle_preview" disabled/);
	assert.match(out, /No upgrades or campaigns are executed/);
	assert.equal(r.result.state().score, model.score);
	await draft.handlers.click();
	assert.deepEqual(r.payloads, [{ name: "draft_dependency_plan", input: { controlId: "supply", ids: dependencies.map((f) => f.id) } }]);
	r.push({ ...model, refreshing: true });
	assert.match(r.draws.at(-1), /data-act="select_dependency_theme"[^>]*disabled/);
	r.push({ ...model, campaignThemes: { supply: mapped.filter((f) => f.id !== dependencies[0].id) } });
	await draft.handlers.click();
	assert.ok(!r.payloads.at(-1).input.ids.includes(dependencies[0].id), "closed groups must be pruned");
	await clear.handlers.click();
	assert.match(r.draws.at(-1), /with Copilot/);
	await all.handlers.click();
	r.push({ ...model, resetEpoch: 1 });
	assert.doesNotMatch(r.draws.at(-1), /selected updates/);
	assert.ok(r.payloads.every((payload) => payload.name === "draft_dependency_plan"));
});

test("incident theme explains file evidence and has real advisory next steps, not a dead campaign box", async () => {
	const select = element({ act: "select", id: "incident" });
	const draft = element({ act: "draft_evidence", id: "incident" });
	const evidence = { codeql: true, "security-md": false, runbook: false };
	const model = { ...complianceModel([], [], { evidence }), source: "github", campaigns: { draft: null, receipts: [] }, threads: {} };
	const r = renderer("compliance-scoreboard", model, [select, draft]);
	await select.handlers.click();
	const out = r.draws.at(-1);
	const detail = out.split('<section class="panel c-detail">')[1];
	assert.match(detail, /Incident response evidence/);
	assert.match(detail, /security contact and a documented response/);
	assert.match(detail, /No alert campaign here/);
	assert.match(detail, /12\/20 = 20 − 2 missing artifacts × 4 points/);
	assert.match(detail, /not proof of a tested response capability/);
	assert.match(detail, /SECURITY.md disclosure policy · <b>not found/);
	assert.match(detail, /Incident response runbook · <b>not found/);
	assert.doesNotMatch(detail, /found \/ enabled|not found \/ disabled/);
	assert.match(detail, /data-act="draft_evidence"/);
	assert.doesNotMatch(detail, /radar-campaign-section|No campaign-eligible alerts|Campaign scope|No open alerts mapped/);
	await draft.handlers.click();
	assert.deepEqual(r.payloads, [{ name: "draft_evidence", input: { id: "incident" } }]);
	assert.equal(r.result.state().score, model.score);
});

test("dependency plans and workflow campaign previews stay separate when switching scope", async () => {
	const findings = fixtureFindings().map((f) => ({ ...f, url: "https://github.com/acme/widgets/security", where: f.path }));
	const model = { ...complianceModel([], findings), source: "github", campaigns: { draft: null, receipts: [] },
		campaignThemes: { supply: findings.filter((f) => f.controlIds.includes("supply")) } };
	const select = element({ act: "select", id: "supply" });
	const deps = element({ act: "select_dependency_theme", control: "supply" });
	const code = element({ act: "toggle_campaign_selection", control: "supply", id: findingId("cs", "actions/unpinned-tag") });
	const show = element({ act: "show_dependency_preview", control: "supply" });
	const r = renderer("compliance-scoreboard", model, [select, deps, code, show]);
	await select.handlers.click();
	await deps.handlers.click();
	assert.match(r.draws.at(-1), /Dependency plan scenario/);
	await code.handlers.click();
	assert.match(r.draws.at(-1), /Campaign scenario · Supply-chain risk/);
	assert.doesNotMatch(r.draws.at(-1), /Dependency plan scenario/);
	await show.handlers.click();
	assert.match(r.draws.at(-1), /Dependency plan scenario/);
	assert.doesNotMatch(r.draws.at(-1), /Campaign scenario ·/);
	assert.deepEqual(r.payloads, []);
});

test("posture campaign hatching covers all impacted themes without adding the Copilot scenario", async () => {
	const raw = { defaultBranch: "trunk", code: [
		{ ...code(1, "refs/heads/trunk"), rule: { id: "actions/unpinned-tag", security_severity_level: "medium" } },
		{ ...code(2, "refs/heads/trunk"), rule: { id: "js/remote-property-injection", security_severity_level: "high" } },
	] };
	const findings = buildLiveFindings(raw);
	const model = { ...complianceModel([], findings), source: "github", threads: {}, preview: true,
		resetEpoch: 0, campaigns: { draft: null, receipts: [] },
		campaignThemes: { change: findings.filter((f) => f.controlIds.includes("change")),
			supply: findings.filter((f) => f.controlIds.includes("supply")), vuln: findings.filter((f) => f.controlIds.includes("vuln")) },
	};
	const select = element({ act: "select", id: "change" });
	const pick = element({ act: "toggle_campaign_selection", control: "change", id: findingId("cs", "actions/unpinned-tag") });
	const clear = element({ act: "clear_campaign_selection", control: "change" });
	const r = renderer("compliance-scoreboard", model, [select, pick, clear]);
	await select.handlers.click();
	await pick.handlers.click();
	let out = r.draws.at(-1);
	assert.match(out, /Campaign scenario · Secure change control/);
	assert.match(out, /selected campaign/);
	assert.match(out, /Campaign lift<\/span><div class="kpi-value"><span class="up">\+4/);
	assert.match(out, /data-act="toggle_preview" disabled/);
	for (const id of ["change", "supply"]) {
		const card = out.match(new RegExp('data-act="select" data-id="' + id + '"[\\s\\S]*?</button>'))[0];
		assert.match(card, /class="ghost[^"]*" style="width:10%"/);
	}
	assert.match(out, /This replaces, never adds to, the Copilot scenario/);
	assert.doesNotMatch(out, /data-act="assign_copilot"|data-act="fix_locally"|data-act="assess_priority"/);
	assert.equal(r.result.state().score, model.score);
	assert.deepEqual(r.payloads, []);
	r.push({ ...model, campaigns: { ...model.campaigns, refreshedAt: "2030-01-01" } });
	assert.match(r.draws.at(-1), /selected campaign/);
	await clear.handlers.click();
	assert.match(r.draws.at(-1), /with Copilot/);
	assert.doesNotMatch(r.draws.at(-1), /selected campaign/);
	await pick.handlers.click();
	r.push({ ...model, campaignThemes: { ...model.campaignThemes, change: [] } });
	assert.doesNotMatch(r.draws.at(-1), /selected campaign/, "closed or stale selections are pruned");
});

test("posture campaign preview explains unknown coverage, branch exclusions and zero lift", async () => {
	const findings = buildLiveFindings({ defaultBranch: "main", code: Array.from({ length: 3 }, (_, index) => ({
		...code(index + 1, index === 0 ? "refs/heads/feature" : "refs/heads/main"),
		rule: { id: `js/critical-${index}`, security_severity_level: "critical" },
	})) });
	const model = { ...complianceModel([], findings), source: "github", threads: {},
		campaignThemes: { vuln: findings }, campaigns: { draft: null, receipts: [] } };
	const select = element({ act: "select", id: "vuln" });
	const pick = element({ act: "toggle_campaign_selection", control: "vuln", id: findings[0].id });
	const r = renderer("compliance-scoreboard", model, [select, pick]);
	await select.handlers.click();
	await pick.handlers.click();
	assert.match(r.draws.at(-1), /1 alert outside the campaign scope remains/);
	assert.match(r.draws.at(-1), /No point gain yet/);
	assert.doesNotMatch(r.draws.at(-1), /Upper bound/);
	const unknown = findings.map((f) => ({ ...f, campaignCount: undefined, campaignRemainder: undefined }));
	r.push({ ...model, ...complianceModel([], unknown), campaignThemes: { vuln: unknown } });
	assert.match(r.draws.at(-1), /Upper bound: branch coverage is unknown/);
	assert.equal(r.result.state().score, model.score);
});

test("Radar and posture render preparation, exclusions, native secret path and shared progress", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	const model = { ...complianceModel(), campaigns: h.service.state(), campaignThemes: { vuln: groups }, source: "github", threads: {} };
	const posture = renderer("compliance-scoreboard", model);
	const page = renderPage("compliance-scoreboard", model);
	assert.match(page, /\.c-detail > \.radar-campaign-section \{ margin: 14px 18px;/);
	assert.match(posture.draws[0], /Select theme/);
	assert.match(posture.draws[0], /Prepared scope: Test/);
	assert.match(posture.draws[0], /Dependency \(dependabot\)/);
	assert.match(posture.draws[0], /#1/);
	assert.doesNotMatch(posture.draws[0], /data-act="publish_campaign"/);
	const reviewed = await h.service.review({ id: d.id, ...fields });
	posture.push({ ...model, campaigns: h.service.state() });
	assert.doesNotMatch(posture.draws.at(-1), /data-act="publish_campaign"/);
	assert.match(posture.draws.at(-1), /Campaign name/);
	const radarModel = { findings: groups.map((f) => ({ ...f, severity: "high", bySeverity: { high: f.count }, path: "test", x: 50, y: 50 })), totals: {}, source: "github", campaigns: h.service.state() };
	const radar = renderer("attack-surface-radar", radarModel);
	assert.doesNotMatch(radar.draws[0], /data-act="toggle_campaign_selection" data-id="dep-test"/);
	assert.doesNotMatch(radar.draws[0], /Include in campaign|data-campaign-select/);
	assert.match(radar.draws[0], /data-act="toggle_campaign_selection" data-id="sec-test"/);
	radar.result.select(groups[0].id);
	assert.match(radar.draws.at(-1), /1 group · 2 alerts/);
	assert.match(radar.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
	radar.push({ ...radarModel, resetEpoch: 1 });
	assert.doesNotMatch(radar.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
	assert.equal(reviewed.status, "reviewed");
	await h.service.reset();
	h.setAlerts([{ number: 3, state: "open", secret_type: "provider_type" }]);
	await h.service.prepare(groups, "secrets", "Credentials");
	posture.push({ ...model, campaigns: h.service.state() });
	assert.match(posture.draws.at(-1), /Open GitHub campaigns/);
	assert.doesNotMatch(posture.draws.at(-1), /data-act="publish_campaign"/);
});

test("renderer forwards exact radar selection, posture theme, reviewed fields and confirmation revision", async () => {
	const h = harness();
	const reviewed = await prepared(h);
	const select = element({ act: "select_campaign_theme", control: "vuln" });
	const theme = element({ act: "prepare_campaign", kind: "code", control: "vuln" });
	const review = element({ act: "review_campaign", id: reviewed.id, prefix: "test-" });
	const publish = element({ act: "publish_campaign", id: reviewed.id, revision: reviewed.revision });
	const form = Object.fromEntries(Object.entries(fields).map(([key, value]) => [`test-${key}`, { value }]));
	const checkbox = { checked: false };
	const model = { ...complianceModel(), source: "github", threads: {}, campaigns: h.service.state(), campaignThemes: { vuln: groups } };
	const r = renderer("compliance-scoreboard", model, [select, theme, review, publish], form, { "[data-campaign-confirm]": checkbox });
	await select.handlers.click();
	await theme.handlers.click();
	assert.deepEqual(r.payloads.at(-1), { name: "prepare_campaign", input: { kind: "code", controlId: "vuln", ids: ["cs-test"] } });
	await review.handlers.click();
	assert.deepEqual(r.payloads.at(-1).input, { id: reviewed.id, ...fields });
	const count = r.payloads.length;
	await publish.handlers.click();
	assert.equal(r.payloads.length, count, "unchecked confirmation must not send a request");
	checkbox.checked = true;
	await publish.handlers.click();
	assert.deepEqual(r.payloads.at(-1).input, { id: reviewed.id, revision: reviewed.revision, confirm: true });
});

test("SSE updates preserve campaign edits but Reset clears them", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	const key = `campaign-${d.id}-name`;
	const fields = { [key]: { value: "My edited campaign", selectionStart: 3, selectionEnd: 3 } };
	const model = { ...complianceModel(), source: "github", threads: {}, campaigns: h.service.state(), resetEpoch: 0 };
	const r = renderer("compliance-scoreboard", model, [], fields, {}, true);
	assert.equal(fields[key].value, "My edited campaign");
	r.push({ ...model, preview: true });
	assert.equal(fields[key].value, "My edited campaign", "unrelated SSE events must not overwrite edits");
	r.push({ ...model, resetEpoch: 1 });
	assert.equal(fields[key].value, "", "Reset must clear transient campaign edits");
});

test("posture selection includes hidden groups, stays theme-local, prunes stale scope and uses direct creation", async () => {
	const h = harness();
	const model = { ...complianceModel(), source: "github", threads: {}, campaigns: h.service.state(), resetEpoch: 0 };
	const vuln = model.controls.find((c) => c.id === "vuln");
	const other = model.controls.find((c) => c.id !== "vuln");
	const mapped = Array.from({ length: 8 }, (_, i) => ({ ...groups[0], id: `cs-${i}`, title: `Rule ${i}`, count: 1, severity: "high", where: "test.ts:1" }));
	model.campaignThemes = { [vuln.id]: mapped, [other.id]: [mapped[0], groups[2]] };
	const select = element({ act: "select", id: vuln.id });
	const all = element({ act: "select_campaign_theme", control: vuln.id });
	const prepare = element({ act: "prepare_campaign", control: vuln.id, kind: "code" });
	const toggle = element({ act: "toggle_campaign_selection", control: other.id, id: mapped[0].id });
	const r = renderer("compliance-scoreboard", model, [select, all, prepare, toggle]);
	await select.handlers.click();
	assert.match(r.draws.at(-1), /Rule 7/);
	await all.handlers.click();
	assert.match(r.draws.at(-1), /8 groups · 8 alerts selected/);
	await prepare.handlers.click();
	assert.deepEqual(r.payloads.at(-1).input.ids, mapped.map((f) => f.id));
	select.dataset.id = other.id;
	await select.handlers.click();
	assert.match(r.draws.at(-1), /Add alerts to prepare a campaign/);
	await toggle.handlers.click();
	assert.match(r.draws.at(-1), /1 group · 1 alert selected/);
	select.dataset.id = vuln.id;
	await select.handlers.click();
	assert.match(r.draws.at(-1), /8 groups · 8 alerts selected/);
	r.push({ ...model, campaignThemes: { ...model.campaignThemes, [vuln.id]: mapped.slice(1) } });
	assert.match(r.draws.at(-1), /7 groups · 7 alerts selected/);
	r.push({ ...model, resetEpoch: 1 });
	assert.match(r.draws.at(-1), /Add alerts to prepare a campaign/);

	const d = await h.service.prepare(groups.slice(0, 1), "code", vuln.title);
	const prefix = `campaign-${d.id}-`;
	const create = element({ act: "create_campaign", id: d.id, control: vuln.id, revision: d.revision, prefix });
	const selected = element({ act: "select", id: vuln.id });
	const fieldsById = Object.fromEntries(["name", "description", "dueDate"].map((key) => [prefix + key, { value: fields[key] }]));
	const ready = renderer("compliance-scoreboard", { ...model, campaigns: h.service.state(), campaignThemes: { [vuln.id]: groups } }, [create, selected], fieldsById);
	await selected.handlers.click();
	assert.match(ready.draws.at(-1), /campaign-submit/);
	assert.match(ready.draws.at(-1), /Create on GitHub/);
	await create.handlers.click();
	assert.deepEqual(ready.payloads.at(-1), { name: "create_campaign", input: { id: d.id, controlId: vuln.id,
		name: fields.name, description: fields.description, dueDate: fields.dueDate, revision: d.revision, confirm: true, ids: ["cs-test"] } });
	ready.push({ ...model, campaigns: h.service.state(), campaignThemes: { [vuln.id]: groups },
		threads: { [vuln.id]: [{ kind: "assess", question: "Assess priority · Test", status: "done", answer: "High, pending evidence." }] } });
	assert.match(ready.draws.at(-1), /AI priority · advisory/);
});

test("Radar findings and campaigns start folded and preserve manual disclosure across redraws", async () => {
	const h = harness();
	const blip = element({ act: "select", id: "sec-test" });
	const disclosure = { dataset: { disclosure: "radar-findings" }, open: false };
	const model = {
		findings: groups.map((f) => ({ ...f, severity: "high", path: "test", x: 50, y: 50 })),
		totals: {}, source: "github", campaigns: h.service.state(), resetEpoch: 0,
	};
	const r = renderer("attack-surface-radar", model, [blip], {}, {}, false,
		{ "details[data-disclosure]": [disclosure] });
	assert.match(r.draws[0], /<details class="radar-findings" data-disclosure="radar-findings"><summary/);
	assert.match(r.draws[0], /All findings &amp; Security campaigns · 3 groups · 10 alerts<\/summary>/);
	assert.match(r.draws[0], /radar-findings-content"><section class="radar-campaign-section"[\s\S]*<div class="grid">[\s\S]*<\/details>$/);
	assert.equal(disclosure.open, false);
	disclosure.open = true;
	await blip.handlers.click();
	assert.equal(disclosure.open, true);
	r.push({ ...model, refreshing: true });
	assert.equal(disclosure.open, true);
	disclosure.open = false;
	r.push(model);
	assert.equal(disclosure.open, false);
	assert.equal(r.payloads.length, 0);
});

test("Radar campaign toggles bind immediately and stay selected when inspecting another blip or receiving SSE", async () => {
	const h = harness();
	const pick = element({ act: "toggle_campaign_selection", id: "cs-test" });
	const blip = element({ act: "select", id: "sec-test" });
	const model = {
		findings: groups.map((f) => ({ ...f, severity: "high", path: "test", x: 50, y: 50 })),
		totals: {}, source: "github", campaigns: h.service.state(), resetEpoch: 0,
	};
	const r = renderer("attack-surface-radar", model, [blip, pick]);
	await pick.handlers.click();
	assert.match(r.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
	await blip.handlers.click();
	assert.match(r.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
	r.push({ ...model, refreshing: true });
	assert.match(r.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
	assert.equal(r.payloads.length, 0, "selection and navigation must remain client-only");
	r.push(model);
	await pick.handlers.click();
	assert.doesNotMatch(r.draws.at(-1), /data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/);
});

test("Radar campaign controls select only from finding cards, separate types, and ignore unsupported or busy toggles", async () => {
	const h = harness();
	const codeToggle = element({ act: "toggle_campaign_selection", id: "cs-test" });
	const secretToggle = element({ act: "toggle_campaign_selection", id: "sec-test" });
	const dependencyToggle = element({ act: "toggle_campaign_selection", id: "dep-test" });
	const clear = element({ act: "clear_campaign_selection" });
	const codePrepare = element({ act: "prepare_campaign", kind: "code" });
	const secretsPrepare = element({ act: "prepare_campaign", kind: "secrets" });
	const model = {
		findings: groups.map((f) => ({ ...f, severity: "high", path: "test", x: 50, y: 50 })),
		totals: {}, source: "github", campaigns: h.service.state(), resetEpoch: 0,
	};
	const r = renderer("attack-surface-radar", model, [codeToggle, secretToggle, dependencyToggle, clear, codePrepare, secretsPrepare]);
	assert.doesNotMatch(r.draws[0], /data-act="prepare_campaign"/, "empty selection must not show dead prepare buttons");
	assert.doesNotMatch(r.draws[0], /class="flow"/);
	assert.doesNotMatch(r.draws[0], /How to read the radar|Add groups with \+|<footer/);
	assert.doesNotMatch(r.draws[0], /radar-journey|<b>Spot<\/b>|<b>Understand<\/b>|<b>Remediate<\/b>/);
	assert.match(r.draws[0], /Ask Copilot about this alert or request a fix\./);
	assert.match(r.draws[0], /All findings[^<]*<\/summary><div class="radar-findings-content"><section class="radar-campaign-section"/);
	assert.match(r.draws[0], /Add alerts to prepare a campaign\./);
	assert.match(r.draws[0], /class="radar-campaign-coverage" aria-hidden="true"/);
	assert.doesNotMatch(r.draws[0].match(/<section class="panel detail[\s\S]*?<\/section>/)[0], /toggle_campaign_selection/);
	await codeToggle.handlers.click();
	assert.match(r.draws.at(-1), /<b>66\.7%<\/b> selected/);
	assert.match(r.draws.at(-1), /data-tooltip="2 alerts selected out of 3 campaign-eligible alerts/);
	assert.equal((r.draws.at(-1).match(/data-act="toggle_campaign_selection" data-id="cs-test" aria-pressed="true"/g) ?? []).length, 1, "only the finding card offers campaign selection");
	for (const toggle of r.draws.at(-1).matchAll(/<button class="radar-campaign-toggle[^>]*>/g)) assert.doesNotMatch(toggle[0], /data-tooltip=|title=/);
	await secretToggle.handlers.click();
	assert.match(r.draws.at(-1), /<b>100%<\/b> selected/);
	assert.doesNotMatch(r.draws.at(-1), /Planned scope|About campaigns/);
	assert.match(r.draws.at(-1), /2 groups · 3 alerts/);
	assert.match(r.draws.at(-1), /Prepare code<\/button>/);
	assert.match(r.draws.at(-1), /Set up secrets<\/button>/);
	await codePrepare.handlers.click();
	assert.deepEqual(r.payloads.at(-1), { name: "prepare_campaign", input: { kind: "code", ids: ["cs-test"] } });
	await secretsPrepare.handlers.click();
	assert.deepEqual(r.payloads.at(-1), { name: "prepare_campaign", input: { kind: "secrets", ids: ["sec-test"] } });
	await dependencyToggle.handlers.click();
	assert.match(r.draws.at(-1), /2 groups · 3 alerts/);
	r.push({ ...model, refreshing: true });
	await codeToggle.handlers.click();
	assert.match(r.draws.at(-1), /2 groups · 3 alerts/);
	r.push({ ...model, campaigns: { ...model.campaigns, busy: true } });
	await secretToggle.handlers.click();
	assert.match(r.draws.at(-1), /2 groups · 3 alerts/);
	r.push({ ...model, findings: model.findings.filter((f) => f.id !== "sec-test") });
	assert.match(r.draws.at(-1), /1 group · 2 alerts/);
	await clear.handlers.click();
	assert.match(r.draws.at(-1), /Add alerts to prepare a campaign\./);
	assert.doesNotMatch(r.draws.at(-1), /data-act="prepare_campaign"/);
	assert.equal(r.payloads.length, 2, "toggle, remove, and clear are client-only actions");
});

test("Radar shows only applicable core actions, keeps receipts, and exposes full KPI and campaign tooltip copy", async () => {
	const h = harness();
	const blip = element({ act: "select", id: "sec-test" });
	const clear = element({ act: "clear_thread", id: "cs-test" });
	const assess = element({ act: "assess_priority", id: "cs-test" });
	const model = {
		findings: groups.map((f) => ({ ...f, severity: "high", path: "test", x: 50, y: 50 })),
		totals: { codeScanning: 2, secretScanning: 1, dependabot: 7 }, source: "github", campaigns: h.service.state(),
		kpis: { open: 10, bySeverity: { high: 10 }, mapped: 10, criticalHigh: 10, criticalHighPct: 100,
			secrets: 1, supplyChainPct: 70, quickWinAlerts: 7, quickWinBumps: 1 },
	};
	const r = renderer("attack-surface-radar", model, [blip, clear, assess]);
	const quick = r.draws[0].match(/<div class="quick">([\s\S]*?)<\/div>/)[1];
	assert.equal((quick.match(/<button/g) ?? []).length, 4);
	assert.match(quick, />Explain<\/button>/);
	assert.match(quick, />Explain<\/button>.*>Assess priority<\/button>.*>Fix locally<\/button>/);
	await assess.handlers.click();
	assert.deepEqual(r.payloads.at(-1), { name: "assess_priority", input: { id: "cs-test" } });
	assert.doesNotMatch(quick, /✦/);
	assert.match(quick, />Fix locally<\/button>/);
	assert.match(quick, />Fix in the cloud<\/button>/);
	assert.doesNotMatch(quick, /suggest_fix|data-q=|data-tooltip=|title=/);
	assert.doesNotMatch(r.draws[0], /data-tooltip="Open alerts:|data-tooltip="Critical &amp; high:/);
	assert.match(r.draws[0], /tabindex="0" data-tooltip="Open secret alerts: 1 · Rotate · values never loaded"/);
	assert.match(r.draws[0], /aria-label="Add to campaign: Test rule \(2 alerts\)"/);
	for (const toggle of r.draws[0].matchAll(/<button class="radar-campaign-toggle[^>]*>/g)) assert.doesNotMatch(toggle[0], /data-tooltip=|title=/);
	await blip.handlers.click();
	const secretQuick = r.draws.at(-1).match(/<div class="quick">([\s\S]*?)<\/div>/)[1];
	assert.equal((secretQuick.match(/<button/g) ?? []).length, 2);
	assert.match(secretQuick, /Assess priority/);
	assert.match(r.draws.at(-1), /Ask Copilot about this alert or how to respond/);
	blip.dataset.id = "dep-test";
	await blip.handlers.click();
	const depQuick = r.draws.at(-1).match(/<div class="quick">([\s\S]*?)<\/div>/)[1];
	assert.equal((depQuick.match(/<button/g) ?? []).length, 3);
	r.push({ ...model, findings: [model.findings[0]], pending: {}, localFixes: {
		"cs-test": { status: "launched", appUrl: "ghapp://sessions/test-session", sessionId: "test-session" },
	}, assigned: { "cs-test": { url: "https://github.com/test/alert/1", number: 1 } } });
	assert.match(r.draws.at(-1), /Open dedicated fix session/);
	assert.match(r.draws.at(-1), /Assigned to Copilot/);
	assert.doesNotMatch(r.draws.at(-1), /data-act="request_copilot"|data-act="assign_copilot"/);
	assert.match(r.draws.at(-1), /data-act="explain_finding" data-id="cs-test" disabled/);
	assert.match(r.draws.at(-1), /data-act="assess_priority" data-id="cs-test" disabled/);
	r.push({ ...model, findings: [model.findings[0]], threads: {
		"cs-test": [{ question: "Explain", status: "done", answer: "This is an availability risk." }],
	} });
	const conversationQuick = r.draws.at(-1).match(/<div class="quick">([\s\S]*?)<\/div>/)[1];
	assert.equal((conversationQuick.match(/<button/g) ?? []).length, 5);
	assert.match(conversationQuick, /class="suggest key radar-conversation-clear" data-act="clear_thread" data-id="cs-test">Clear<\/button>/);
	assert.doesNotMatch(r.draws.at(-1), /Clear conversation/);
	r.push({ ...model, findings: [model.findings[0]], threads: { "cs-test": [{ kind: "assess", question: "Assess priority", status: "done", answer: "High: evidence needs review." }] } });
	assert.match(r.draws.at(-1), /AI priority · advisory/);
	r.push({ ...model, findings: [model.findings[0]], threads: { "cs-test": [{ kind: "assess", question: "Assess priority", status: "done", offline: true, answer: "No AI priority was assigned." }] } });
	assert.match(r.draws.at(-1), /assessment unavailable/);
	await clear.handlers.click();
	assert.deepEqual(r.payloads.at(-1), { name: "clear_thread", input: { id: "cs-test" } });
	r.push({ ...model, findings: [model.findings[2]] });
	assert.match(r.draws.at(-1), /No campaign-eligible alerts/);
	assert.doesNotMatch(r.draws.at(-1), /NaN|Infinity/);
});

test("Radar tooltips show full text on hover and focus outside clipped cells and dismiss on Escape", () => {
	const h = harness();
	const tip = { style: {}, hidden: true, getBoundingClientRect: () => ({ width: 280, height: 48 }) };
	const trigger = element({ tooltip: "Add to campaign: A long finding title <script>" });
	const attributes = {};
	trigger.getBoundingClientRect = () => ({ left: 950, top: 650, bottom: 684 });
	trigger.setAttribute = (name, value) => { attributes[name] = value; };
	trigger.removeAttribute = (name) => { delete attributes[name]; };
	renderer("attack-surface-radar", { findings: [], totals: {}, source: "github", campaigns: h.service.state() },
		[], { "radar-tooltip": tip }, {}, false, { "[data-tooltip]": [trigger] });
	trigger.handlers.mouseenter();
	assert.equal(tip.hidden, false);
	assert.equal(tip.textContent, trigger.dataset.tooltip, "tooltip uses text, never HTML");
	assert.equal(tip.style.left, "710px");
	assert.equal(tip.style.top, "596px");
	assert.equal(attributes["aria-describedby"], "radar-tooltip");
	trigger.handlers.keydown({ key: "Escape" });
	assert.equal(tip.hidden, true);
	assert.equal(attributes["aria-describedby"], undefined);
	trigger.handlers.focus();
	assert.equal(tip.hidden, false);
	trigger.handlers.blur();
	assert.equal(tip.hidden, true);
});

test("Radar creation form sends three fields, exact selection and explicit confirmation, then lists the GitHub receipt", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	const prefix = `campaign-${d.id}-`;
	const button = element({ act: "create_campaign", id: d.id, revision: d.revision, prefix });
	const form = Object.fromEntries(["name", "description", "dueDate"].map((key) => [prefix + key, { value: fields[key] }]));
	const model = { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })), totals: {}, source: "github", campaigns: h.service.state() };
	const r = renderer("attack-surface-radar", model, [button], form, {}, false, {}, async ({ name, input }) => {
		assert.equal(name, "create_campaign");
		await h.service.create(input);
		return { ok: true };
	});
	assert.match(r.draws[0], /2 alerts included:<\/span>/);
	assert.match(r.draws[0], /security\/code-scanning\/1[^>]*>#1<\/a>/);
	assert.match(r.draws[0], /security\/code-scanning\/2[^>]*>#2<\/a>/);
	assert.match(r.draws[0], /Create on GitHub/);
	assert.doesNotMatch(r.draws[0], /Local campaign preparation|Manager GitHub login|Review publication|data-campaign-confirm|>Cancel</);
	assert.equal((r.draws[0].match(/data-act="create_campaign"/g) || []).length, 1, "one creation action in the campaign banner");
	const compactForm = r.draws[0].match(/<section class="radar-campaign-form"[\s\S]*?<\/section>/)[0];
	assert.equal((compactForm.match(/<input /g) || []).length, 3);
	assert.doesNotMatch(compactForm, /<h3>|<button |<details>|@mona|Creates on GitHub/);
	assert.match(r.draws[0], /class="primary campaign-submit" data-act="create_campaign"/);
	await button.handlers.click();
	assert.deepEqual(r.payloads[0].input, { id: d.id, name: fields.name, description: fields.description,
		dueDate: fields.dueDate, revision: d.revision, confirm: true, ids: ["cs-test"] });
	r.push({ ...model, campaigns: h.service.state() });
	assert.doesNotMatch(r.draws.at(-1), /radar-campaign-form/);
	assert.match(r.draws.at(-1), /https:\/\/github.com\/orgs\/acme\/security\/campaigns\/7/);
});

test("Radar keeps preparation and the timestamped receipt in one campaign section without an extra header or refresh button", async () => {
	const h = harness();
	let draft = await h.service.prepare(groups, "code", "Test");
	await h.service.create(creationInput(draft));
	draft = await h.service.prepare(groups, "code", "Next");
	const r = renderer("attack-surface-radar", { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })),
		totals: {}, source: "github", campaigns: h.service.state() });
	const section = r.draws[0].split('<section class="radar-campaign-section"')[1].split('<div class="grid">')[0];
	assert.match(section, /class="radar-campaign-form"/);
	assert.match(section, /class="campaign-tracking" aria-label="Created campaigns"/);
	assert.doesNotMatch(section, /class="panel|Real GitHub state|Reset does not delete campaigns|Last successful refresh/);
	assert.doesNotMatch(section, /Campaigns submitted from this session|campaign-tracking-head|data-act="refresh_campaigns"/);
	assert.match(section, /<div class="campaign-receipt-head"><a[^>]*>[\s\S]*?<\/a><time/);
	assert.match(section, /datetime="2030-01-01T12:00:00.000Z"/);
	assert.match(section, /Last refresh:/);
	assert.match(r.draws[0], /data-act="refresh"/);
	assert.equal(h.service.state().draft.id, draft.id);
	const posture = renderer("compliance-scoreboard", { ...complianceModel(), source: "github", campaigns: h.service.state() });
	assert.doesNotMatch(posture.draws[0], /Campaigns submitted from this session|data-act="refresh_campaigns"/);
	assert.match(posture.draws[0], /Last refresh:/);
});

test("Radar shows one last-refresh timestamp on the first published campaign and labels the first step Prepare campaign", () => {
	const model = { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })), totals: {}, source: "github",
		campaigns: { draft: null, refreshedAt: new Date(time).toISOString(), receipts: [7, 8].map((number) => ({
			id: `receipt-${number}`, repo, status: "published", campaign: { number, name: `Campaign ${number}`,
				url: `https://github.com/orgs/acme/security/campaigns/${number}`, stats: { open_count: 2, closed_count: 0, in_progress_count: 0 } },
		})) } };
	const r = renderer("attack-surface-radar", model);
	r.result.select("cs-test");
	assert.match(r.draws.at(-1), /data-act="prepare_campaign" data-kind="code"[^>]*>Prepare campaign/);
	assert.equal((r.draws.at(-1).match(/Last refresh:/g) || []).length, 1);
	assert.match(r.draws.at(-1), /Campaign 7 · #7<\/b> ↗<\/a><time/);
	assert.doesNotMatch(r.draws.at(-1), /Campaigns submitted from this session|data-act="refresh_campaigns"/);
});

test("Radar replaces final creation with Update scope when the selected groups differ from the open form", async () => {
	const h = harness();
	await h.service.prepare(groups, "code", "Test");
	const model = { findings: [...groups, { ...groups[0], id: "cs-extra" }].map((f) => ({ ...f, path: "test", severity: "high" })),
		totals: {}, source: "github", campaigns: h.service.state() };
	const r = renderer("attack-surface-radar", model);
	assert.match(r.draws[0], /data-act="create_campaign"/);
	r.result.select("cs-extra");
	assert.match(r.draws.at(-1), /data-act="prepare_campaign" data-kind="code"[^>]*>Update scope/);
	assert.doesNotMatch(r.draws.at(-1), /data-act="create_campaign"/);
});

test("Clear selection remains available when the last group is removed from an open compact form", async () => {
	const h = harness();
	await h.service.prepare(groups, "code", "Test");
	const toggle = element({ act: "toggle_campaign_selection", id: "cs-test" });
	const model = { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })),
		totals: {}, source: "github", campaigns: h.service.state() };
	const r = renderer("attack-surface-radar", model, [toggle]);
	await toggle.handlers.click();
	assert.doesNotMatch(r.draws.at(-1), /aria-pressed="true"/);
	assert.match(r.draws.at(-1), /data-act="clear_campaign_selection"/);
	assert.match(r.draws.at(-1), /radar-campaign-form/);
	assert.doesNotMatch(r.draws.at(-1), /data-act="create_campaign"/);
});

test("Clear selection discards and persists the open form, clears selection and preserves real campaign receipts", async () => {
	const h = harness({ data: { draft: null, receipts: [{
		id: "published", status: "published", campaign: { number: 7, url: "https://github.com/orgs/acme/security/campaigns/7" },
	}] } });
	await h.service.prepare(groups, "code", "Test");
	const clear = element({ act: "clear_campaign_selection" });
	const model = { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })), totals: {}, source: "github", campaigns: h.service.state() };
	const r = renderer("attack-surface-radar", model, [clear], {}, {}, false, {}, async ({ name }) => {
		assert.equal(name, "discard_campaign");
		await h.service.reset();
		return { ok: true };
	});
	assert.match(r.draws[0], /radar-campaign-form/);
	await clear.handlers.click();
	assert.doesNotMatch(r.draws.at(-1), /radar-campaign-form|aria-pressed="true"/);
	assert.match(r.draws.at(-1), /Add alerts to prepare a campaign/);
	assert.equal(h.saved.at(-1).draft, null);
	assert.equal(h.service.state().receipts[0].status, "published");
	assert.match(r.draws.at(-1), /security\/campaigns\/7/);
});

test("Clear selection preserves the form and selected groups when discarding fails and displays the error", async () => {
	const h = harness();
	const d = await h.service.prepare(groups, "code", "Test");
	const clear = element({ act: "clear_campaign_selection" });
	const model = { findings: groups.map((f) => ({ ...f, path: "test", severity: "high" })), totals: {}, source: "github", campaigns: h.service.state() };
	const r = renderer("attack-surface-radar", model, [clear], {}, {}, false, {},
		async () => ({ ok: false, json: async () => ({ error: "Could not save discarded form." }) }));
	await clear.handlers.click();
	assert.match(r.draws.at(-1), /radar-campaign-form/);
	assert.match(r.draws.at(-1), /aria-pressed="true"/);
	assert.match(r.draws.at(-1), /role="alert">Could not save discarded form/);
	assert.equal(h.service.state().draft.id, d.id);
});

for (const canvasId of ["compliance-scoreboard"]) {
	test(`${canvasId} campaign confirmation controls bind on every render without a prior API call`, async () => {
		const h = harness();
		const d = await prepared(h);
		const confirm = element({});
		const absent = element({ campaignAbsent: "unknown-receipt" });
		const publish = element({ act: "publish_campaign", id: d.id, revision: d.revision });
		const release = element({ act: "acknowledge_campaign_absent", id: "unknown-receipt" });
		publish.disabled = true;
		release.disabled = true;
		const model = {
			...complianceModel(), findings: groups.map((f) => ({ ...f, severity: "high", path: "test", x: 50, y: 50 })),
			source: "github", threads: {}, campaigns: h.service.state(), resetEpoch: 0, refreshing: false,
		};
		const r = renderer(canvasId, model, [publish, release], {}, {
			'[data-act="publish_campaign"]': publish,
			'[data-act="acknowledge_campaign_absent"][data-id="unknown-receipt"]': release,
		}, false, { "[data-campaign-confirm]": [confirm], "[data-campaign-absent]": [absent] });
		assert.equal(typeof confirm.handlers.change, "function");
		assert.equal(typeof absent.handlers.change, "function", "absence acknowledgment cannot depend on a publish confirmation being rendered");
		confirm.checked = true;
		confirm.handlers.change();
		assert.equal(publish.disabled, false);
		r.push({ ...model, campaigns: { ...model.campaigns, busy: true } });
		confirm.handlers.change();
		assert.equal(publish.disabled, true);
		absent.checked = true;
		absent.handlers.change();
		assert.equal(release.disabled, true);
		r.push(model);
		absent.handlers.change();
		assert.equal(release.disabled, false);
		assert.equal(r.payloads.length, 0, "confirmation alone must never publish or acknowledge absence");
	});
}
