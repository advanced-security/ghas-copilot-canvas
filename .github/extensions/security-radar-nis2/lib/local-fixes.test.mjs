import assert from "node:assert/strict";
import test from "node:test";
import { createLocalFixLauncher, localFixHandoff } from "./local-fixes.mjs";

function fixture(send = async () => {}) {
	const records = {};
	const messages = [];
	const timers = [];
	let saved = 0;
	let updates = 0;
	const launcher = createLocalFixLauncher({
		records,
		parentSessionId: "parent-1",
		send: async (message) => { messages.push(message); await send(message); },
		persist: async () => { saved++; },
		broadcast: () => { updates++; },
		log: () => {},
		schedule: (callback) => { timers.push(callback); return timers.length; },
		cancel: () => {},
	});
	return { launcher, records, messages, timers, counts: () => ({ saved, updates }) };
}

const job = {
	canvasId: "attack-surface-radar", instanceId: "radar-panel", id: "cs-command",
	requestId: "request-1", title: "Command injection", prompt: "Apply the safe fix; run the focused build.",
};
const receipt = {
	id: job.id, requestId: job.requestId, sessionId: "child-1", appUrl: "ghapp://sessions/child-1",
};

for (const canvasId of ["attack-surface-radar", "compliance-scoreboard"]) {
	test(`${canvasId} routes implementation to a worktree child, not the canvas chat`, async () => {
		const f = fixture();
		const request = { ...job, canvasId };
		const record = await f.launcher.launch(request);
		assert.equal(record.status, "launching");
		assert.equal(f.messages.length, 1);
		const prompt = f.messages[0].prompt;
		assert.match(prompt, /Use create_session/);
		assert.match(prompt, /workspace_type "worktree"/);
		assert.match(prompt, /execution_location "local"/);
		assert.match(prompt, /kickoff \{ mode: "autopilot"/);
		assert.match(prompt, /Do not implement it in this conversation/);
		assert.match(prompt, /do not call navigate_to/);
		assert.match(prompt, /never fall back to editing here/);
		assert.ok(prompt.includes(job.prompt));
		assert.match(prompt, /actionName "record_fix_session"/);
		assert.match(prompt, /Do not commit, push, or open a PR unless/);
		await f.launcher.recordSession(canvasId, receipt);
		assert.equal(record.status, "launched");
		assert.equal(record.sessionId, receipt.sessionId);
		assert.equal(record.appUrl, receipt.appUrl);
		assert.deepEqual(f.counts(), { saved: 2, updates: 2 });
	});
}

test("repeated and cross-canvas clicks reuse the launch, including after reload", async () => {
	const f = fixture();
	const first = await f.launcher.launch(job);
	await f.launcher.launch({ ...job, requestId: "another" });
	await f.launcher.launch({ ...job, canvasId: "attack-surface-radar", requestId: "third" });
	assert.equal(f.messages.length, 1);
	await f.launcher.recordSession(job.canvasId, receipt);
	const restored = JSON.parse(JSON.stringify(f.records));
	const launcher = createLocalFixLauncher({
		records: restored, send: () => assert.fail("must not send"), persist: async () => {},
		broadcast: () => {}, log: () => {},
	});
	assert.deepEqual(await launcher.launch(job), first);
});

test("stale, wrong-canvas, malformed and conflicting receipts are rejected", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	await assert.rejects(f.launcher.recordSession("compliance-scoreboard", receipt), /matching/);
	await assert.rejects(f.launcher.recordSession(job.canvasId, { ...receipt, requestId: "stale" }), /matching/);
	await assert.rejects(f.launcher.recordSession(job.canvasId, { ...receipt, appUrl: "javascript:alert(1)" }), /actual/);
	await assert.rejects(f.launcher.recordSession(job.canvasId, { ...receipt, appUrl: "ghapp://sessions/other" }), /does not match/);
	await assert.rejects(f.launcher.recordSession(job.canvasId, { ...receipt, sessionId: "parent-1", appUrl: "ghapp://sessions/parent-1" }), /different session/);
	await f.launcher.recordSession(job.canvasId, receipt);
	await assert.rejects(f.launcher.recordSession(job.canvasId, { ...receipt, sessionId: "child-2", appUrl: "ghapp://sessions/child-2" }), /already/);
	assert.equal(f.records[job.id].sessionId, receipt.sessionId);
});

test("delivery errors are visible, never implement locally, and do not retry", async () => {
	const f = fixture(async () => { throw new Error("coordinator disconnected"); });
	await assert.rejects(f.launcher.launch(job), /disconnected/);
	assert.equal(f.records[job.id].status, "unknown");
	assert.match(f.records[job.id].error, /coordinator disconnected/);
	await f.launcher.launch(job);
	assert.equal(f.messages.length, 1);
});

test("timeout is not success; late receipts recover without starting another session", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	f.timers[0]();
	assert.equal(f.records[job.id].status, "unknown");
	assert.match(f.records[job.id].error, /not confirmed/);
	await f.launcher.launch(job);
	assert.equal(f.messages.length, 1);
	await f.launcher.recordSession(job.canvasId, receipt);
	assert.equal(f.records[job.id].status, "launched");
	assert.equal(f.records[job.id].error, null);
});

test("recorded launch is not downgraded by a stale timeout", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	await f.launcher.recordSession(job.canvasId, receipt);
	f.timers[0]();
	assert.equal(f.records[job.id].status, "launched");
});

test("confirmed session receipt survives a later delivery rejection", async () => {
	const gate = Promise.withResolvers();
	const f = fixture(() => gate.promise);
	const launching = f.launcher.launch(job);
	while (!f.messages.length) await Promise.resolve();
	await f.launcher.recordSession(job.canvasId, receipt);
	gate.reject(new Error("late transport failure"));
	const record = await launching;
	assert.equal(record.status, "launched");
	assert.equal(record.appUrl, receipt.appUrl);
	assert.equal(record.error, null);
	assert.equal(f.messages.length, 1);
	assert.deepEqual(f.counts(), { saved: 2, updates: 2 });
});

test("a released request's late delivery rejection cannot change a newer launch", async () => {
	const gate = Promise.withResolvers();
	let calls = 0;
	const f = fixture(() => ++calls === 1 ? gate.promise : Promise.resolve());
	const old = f.launcher.launch(job);
	while (!f.messages.length) await Promise.resolve();
	f.timers[0]();
	await f.launcher.acknowledgeAbsent({ id: job.id, requestId: job.requestId, confirm: true });
	const next = await f.launcher.launch({ ...job, requestId: "new-request" });
	const before = f.counts();
	gate.reject(new Error("old send failed"));
	await old;
	assert.deepEqual(f.counts(), before);
	assert.equal(f.records[job.id], next);
	assert.equal(next.status, "launching");
	await f.launcher.recordSession(job.canvasId, { ...receipt, requestId: next.requestId });
});

test("only explicit absence confirmation releases the exact unknown launch and never retries", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	await assert.rejects(f.launcher.acknowledgeAbsent({ ...receipt, confirm: true }), /Explicitly confirm/);
	f.timers[0]();
	for (const input of [{ id: job.id, requestId: job.requestId }, { id: job.id, requestId: "stale", confirm: true }]) {
		await assert.rejects(f.launcher.acknowledgeAbsent(input), /Explicitly confirm/);
	}
	const released = await f.launcher.acknowledgeAbsent({ id: job.id, requestId: job.requestId, confirm: true });
	assert.deepEqual(released, { id: job.id, released: true });
	assert.deepEqual(f.records, {});
	assert.equal(f.messages.length, 1);
	await assert.rejects(f.launcher.recordSession(job.canvasId, receipt), /matching/);
	const next = await f.launcher.launch({ ...job, requestId: "new-request" });
	assert.equal(next.requestId, "new-request");
	assert.equal(f.messages.length, 2);
	await f.launcher.recordSession(job.canvasId, { ...receipt, requestId: "new-request" });
});

test("failed absence persistence restores the protected launch receipt", async () => {
	const records = { [job.id]: { ...job, status: "unknown" } };
	const launcher = createLocalFixLauncher({
		records, send() { assert.fail("must not retry"); }, broadcast() {}, log() {},
		persist: async () => { throw new Error("disk full"); },
	});
	await assert.rejects(launcher.acknowledgeAbsent({ id: job.id, requestId: job.requestId, confirm: true }), /disk full/);
	assert.equal(records[job.id].status, "unknown");
	assert.equal(records[job.id].requestId, job.requestId);
});

test("reset persists an empty launch ledger and permits a fresh session", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	await f.launcher.recordSession(job.canvasId, receipt);
	await f.launcher.reset();
	assert.deepEqual(f.records, {});
	assert.equal(f.messages.length, 1, "reset must not contact or stop the child session");
	await assert.rejects(f.launcher.recordSession(job.canvasId, receipt), /matching/);
	const fresh = await f.launcher.launch({ ...job, requestId: "next-session" });
	assert.equal(fresh.requestId, "next-session");
	assert.equal(f.messages.length, 2);
	await assert.rejects(f.launcher.recordSession(job.canvasId, receipt), /matching/);
	await f.launcher.recordSession(job.canvasId, { ...receipt, requestId: "next-session", sessionId: "child-2", appUrl: "ghapp://sessions/child-2" });
	assert.equal(f.records[job.id].sessionId, "child-2");
});

test("reset blocks active launches and retains unknown launches for deduplication and late receipts", async () => {
	const f = fixture();
	await f.launcher.launch(job);
	await assert.rejects(f.launcher.reset(), /launch to finish/);
	assert.equal(f.records[job.id].status, "launching");
	f.timers[0]();
	await f.launcher.reset();
	f.timers[0]();
	assert.equal(f.records[job.id].status, "unknown");
	await f.launcher.launch({ ...job, requestId: "duplicate" });
	assert.equal(f.messages.length, 1);
	await f.launcher.recordSession(job.canvasId, receipt);
	assert.equal(f.records[job.id].sessionId, receipt.sessionId);
});

test("reset retains delivery-error records without resending and still accepts their late receipt", async () => {
	const f = fixture(async () => { throw new Error("delivery uncertain"); });
	await assert.rejects(f.launcher.launch(job), /delivery uncertain/);
	await f.launcher.reset();
	assert.equal(f.records[job.id].status, "unknown");
	await f.launcher.launch(job);
	assert.equal(f.messages.length, 1);
	await f.launcher.recordSession(job.canvasId, receipt);
	assert.equal(f.records[job.id].status, "launched");
});

test("an unsent launch is removed after initial persistence failure and can be retried", async () => {
	const records = {};
	let fail = true;
	let sent = 0;
	const launcher = createLocalFixLauncher({
		records, send: async () => { sent++; }, broadcast() {}, log() {},
		persist: async () => { if (fail) throw new Error("disk full"); },
	});
	await assert.rejects(launcher.launch(job), /No request was sent; retry/);
	assert.deepEqual(records, {});
	assert.equal(sent, 0);
	fail = false;
	const retry = await launcher.launch({ ...job, requestId: "retry" });
	assert.equal(retry.requestId, "retry");
	assert.equal(retry.status, "launching");
	assert.equal(sent, 1);
	await launcher.recordSession(job.canvasId, { ...receipt, requestId: "retry" });
});

test("repository identity is case-insensitive for both restored and new launch records", async () => {
	const f = fixture();
	await f.launcher.launch({ ...job, repo: "Acme/Widgets" });
	assert.equal(f.records[job.id].repo, "acme/widgets");
	f.records[job.id].repo = "ACME/WIDGETS";
	await f.launcher.launch({ ...job, repo: "acme/widgets", requestId: "duplicate" });
	assert.equal(f.messages.length, 1);
	await f.launcher.recordSession(job.canvasId, receipt);
});

test("a failed reset restores the existing session link instead of claiming success", async () => {
	const records = {};
	let fail = false;
	const launcher = createLocalFixLauncher({
		records, send: async () => {}, broadcast: () => {}, log: () => {},
		persist: async () => { if (fail) throw new Error("disk unavailable"); },
	});
	await launcher.launch(job);
	await launcher.recordSession(job.canvasId, receipt);
	fail = true;
	await assert.rejects(launcher.reset(), /disk unavailable/);
	assert.equal(records[job.id].sessionId, receipt.sessionId);
	assert.equal(records[job.id].status, "launched");
});

test("handoff preserves the complete task and requires real session links", () => {
	const prompt = localFixHandoff({ ...job, prompt: "Task line one\nTask line two" });
	assert.match(prompt, /Task line one\nTask line two/);
	assert.match(prompt, /Never construct a URL/);
	assert.match(prompt, /Leave base_branch and model overrides unset/);
	assert.doesNotMatch(prompt, /git switch|git checkout|kickoff_mode/);
});
