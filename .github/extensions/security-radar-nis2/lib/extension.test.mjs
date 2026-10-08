import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as nodeModule from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate, setTimeout as sleep } from "node:timers/promises";

const skip = typeof nodeModule.registerHooks !== "function" && "SDK mocking requires Node 22.15+";
const ARTIFACTS = "extensions/security-radar-nis2/artifacts";
let importSeq = 0;

// Loads extension.mjs against a mocked SDK and a mocked child_process, then hands the helpers to the test body.
async function withExtension({ gh, seed }, body) {
	const home = await mkdtemp(join(tmpdir(), "security-radar-test-"));
	const previousHome = process.env.COPILOT_HOME;
	process.env.COPILOT_HOME = home;
	if (seed) await seed(join(home, ARTIFACTS));
	const handlers = new Map();
	const sent = [];
	const previousSetInterval = globalThis.setInterval;
	const progressTicks = [];
	globalThis.setInterval = (callback, delay, ...args) => {
		if (delay === 300000) progressTicks.push(callback);
		return previousSetInterval(callback, delay, ...args);
	};
	const hooks = nodeModule.registerHooks({
		resolve(specifier, context, next) {
			if (specifier === "@github/copilot-sdk/extension" || specifier === "node:child_process") {
				return { url: `test:${specifier}`, shortCircuit: true };
			}
			return next(specifier, context);
		},
		load(url, context, next) {
			if (url === "test:node:child_process") return {
				format: "module", shortCircuit: true,
				source: `import { promisify } from "node:util";
					export function execFile(...args) { args.at(-1)(new Error("GitHub disabled in test")); }
					execFile[promisify.custom] = async (...args) => {
						if (globalThis.canvasTestExecFile) return globalThis.canvasTestExecFile(...args);
						throw new Error("GitHub disabled in test");
					};`,
			};
			if (url === "test:@github/copilot-sdk/extension") return {
				format: "module", shortCircuit: true,
				source: `export class CanvasError extends Error { constructor(code, message) { super(message); this.code = code; } }
					export function createCanvas(options) { return options; }
					export async function joinSession(options) {
						globalThis.canvasTestConfig = options;
						await globalThis.canvasTestRehydrate(options.canvases);
						return globalThis.canvasTestSession;
					}`,
			};
			return next(url, context);
		},
	});
	const ctx = { gh, home, sent, handlers, opens: [], progressTicks };
	globalThis.canvasTestExecFile = (...args) => ctx.gh(...args);
	globalThis.canvasTestSession = {
		sessionId: "test-parent",
		workspacePath: home,
		log() {},
		on(type, handler) {
			const set = handlers.get(type) ?? new Set();
			handlers.set(type, set);
			set.add(handler);
			return () => set.delete(handler);
		},
		async send(message) {
			sent.push(message);
			if (message.prompt.includes("Use create_session")) return "launch-message";
			queueMicrotask(() => {
				for (const handler of handlers.get("user.message") ?? []) handler({ data: { content: message.prompt } });
				for (const handler of handlers.get("assistant.message") ?? []) handler({ data: { content: "Use the repository's safe helper." } });
			});
			return "answer-message";
		},
	};
	globalThis.canvasTestRehydrate = async (canvases) => {
		const previousTicks = progressTicks.length;
		const canvas = canvases.find((c) => c.id === "attack-surface-radar");
		const instanceId = `test-${canvas.id}`;
		await canvas.open({ instanceId });
		ctx.opens.push({ canvas, instanceId });
		assert.equal(progressTicks.length, previousTicks, "rehydration must not start polling before campaign service initialization");
	};
	try {
		await import(`../extension.mjs?run-${++importSeq}`);
		ctx.canvases = globalThis.canvasTestConfig.canvases;
		ctx.invoke = (canvasId, name, input) => ctx.canvases.find((c) => c.id === canvasId).actions.find((a) => a.name === name)
			.handler({ canvasId, input });
		ctx.waitFor = async (check) => {
			for (let attempt = 0; attempt < 500; attempt++) {
				const value = await check();
				if (value) return value;
				await sleep(10);
			}
			throw new Error("condition was not met in time");
		};
		await body(ctx);
	} finally {
		for (const { canvas, instanceId } of ctx.opens) await canvas.onClose({ instanceId });
		hooks.deregister();
		delete globalThis.canvasTestSession;
		delete globalThis.canvasTestConfig;
		delete globalThis.canvasTestExecFile;
		delete globalThis.canvasTestRehydrate;
		globalThis.setInterval = previousSetInterval;
		if (previousHome === undefined) delete process.env.COPILOT_HOME;
		else process.env.COPILOT_HOME = previousHome;
		await rm(home, { recursive: true });
	}
}

const codeAlert = (number, rule, path, line, severity = "warning") => ({
	number, state: "open", html_url: `https://github.com/acme/widgets/security/code-scanning/${number}`,
	rule: { id: rule, severity, description: `Rule ${rule}` },
	most_recent_instance: { ref: "refs/heads/main", location: { path, start_line: line } },
});
const campaignId = (index) => `cs-js-campaign-${index}`;
const liveCode = Array.from({ length: 8 }, (_, index) => codeAlert(index + 100, `js/campaign-${index}`, "src/test.js", index + 1));
const workflowAlert = codeAlert(150, "actions/unpinned-tag", ".github/workflows/ci.yml", 12);
const liveSecrets = [{ number: 200, state: "open", secret_type: "provider_key", secret: "NEVER-COPY-ME" }];
const liveDependencies = [{
	number: 300, state: "open", dependency: { package: { name: "lodash", ecosystem: "npm" } }, security_advisory: { severity: "high" },
}];

// Answers the gh calls a sync makes. Extra routes can be added through the handlers argument.
function githubMock({ code = [...liveCode, workflowAlert], dependabot = liveDependencies, secrets = liveSecrets, repo = "acme/widgets", handlers } = {}) {
	return async (command, args, options) => {
		assert.equal(command, "gh");
		if (args[0] === "repo") {
			assert.equal(options.cwd, process.cwd(), "repository resolution must use the checkout, not the session artifact directory");
			return { stdout: `${repo}\n` };
		}
		const custom = await handlers?.(args);
		if (custom) return custom;
		if (args.includes("user")) return { stdout: JSON.stringify({ login: "mona" }) };
		const path = args.find((value) => value.startsWith("repos/") || value.startsWith("orgs/"));
		if (path.includes("code-scanning/alerts")) return { stdout: JSON.stringify([code]) };
		if (path.includes("secret-scanning/alerts")) return { stdout: JSON.stringify([secrets]) };
		if (path.includes("dependabot/alerts")) return { stdout: JSON.stringify([dependabot]) };
		if (args.includes("--jq")) {
			assert.match(args[args.indexOf("--jq") + 1], /default_branch/);
			return { stdout: JSON.stringify({ default_branch: "main" }) };
		}
		return { stdout: JSON.stringify({ id: 42, owner: { type: "Organization" }, default_branch: "main" }) };
	};
}

const settled = (h, check) => h.waitFor(async () => {
	const state = await h.invoke("attack-surface-radar", "get_state", {});
	return !state.refreshing && check(state) ? state : null;
});
const synced = (h) => settled(h, (state) => state.source === "github");

test("registers exactly the radar and the NIS2 / DORA canvases", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		assert.deepEqual(h.canvases.map((c) => c.id), ["attack-surface-radar", "compliance-scoreboard"]);
		assert.deepEqual(h.canvases.map((c) => c.displayName), ["Attack surface radar", "NIS2 / DORA score"]);
		for (const canvas of h.canvases) {
			const names = canvas.actions.map((a) => a.name);
			for (const name of ["get_state", "refresh", "reset_demo", "record_fix_session", "prepare_campaign", "publish_campaign"]) {
				assert.ok(names.includes(name), `${canvas.id} exposes ${name}`);
			}
			assert.doesNotMatch(canvas.description, /demo/i);
		}
	});
});

test("starts empty and explains why when neither gh nor git can resolve the repository", { skip }, async () => {
	await withExtension({ gh: async () => { throw new Error("GitHub disabled in test"); } }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "none");
		assert.deepEqual(state.findings, []);
		assert.equal(state.repo, null);
		assert.match(state.repoError, /Could not determine the GitHub repository/);
		assert.equal(state.refreshError, state.repoError);
		const posture = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.equal(posture.source, "none");
		assert.deepEqual(posture.controls.flatMap((c) => c.findings), []);
		await assert.rejects(h.invoke("attack-surface-radar", "prepare_campaign", { ids: ["cs-js-campaign-0"], kind: "code" }), /Refresh live/);
		const opened = await h.opens[0].canvas.open({ instanceId: h.opens[0].instanceId });
		assert.equal((await fetch(opened.url)).status, 200);
	});
});

test("reports an unauthenticated gh as an empty state with guidance", { skip }, async () => {
	const gh = async (command, args) => {
		if (args[0] === "repo") return { stdout: "acme/widgets\n" };
		const error = new Error("gh: To get started with GitHub CLI, please run: gh auth login");
		error.stderr = error.message;
		throw error;
	};
	await withExtension({ gh }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "none");
		assert.equal(state.repo, "acme/widgets");
		assert.equal(state.repoError, null);
		assert.match(state.refreshError, /Could not sync from GitHub: gh is not authenticated/);
	});
});

test("falls back to the origin remote when gh cannot name the repository", { skip }, async () => {
	const live = githubMock();
	const gh = async (command, args, options) => {
		if (command === "git") {
			assert.deepEqual(args, ["remote", "get-url", "origin"]);
			return { stdout: "git@github.com:acme/widgets.git\n" };
		}
		if (args[0] === "repo") throw new Error("gh is unavailable");
		return live(command, args, options);
	};
	await withExtension({ gh }, async (h) => {
		await synced(h);
		const state = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(state.repo, "acme/widgets");
		assert.equal(state.repoError, null);
		assert.ok(state.findings.length > 0);
		assert.ok(state.findings.every((f) => f.url.startsWith("https://github.com/acme/widgets/")));
	});
});

test("auto-syncs live alerts on first open and builds generic finding ids", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const radar = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(radar.repo, "acme/widgets");
		assert.equal(radar.refreshError, null);
		assert.deepEqual(radar.totals, { codeScanning: 9, dependabot: 1, secretScanning: 1, asOf: radar.totals.asOf });
		const ids = radar.findings.map((f) => f.id);
		assert.ok(ids.includes(campaignId(0)));
		assert.ok(ids.includes("cs-actions-unpinned-tag"));
		assert.ok(ids.includes("dep-lodash"));
		assert.ok(ids.includes("sec-provider-key"));
		assert.doesNotMatch(JSON.stringify(radar), /NEVER-COPY-ME/);
		const posture = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.equal(posture.source, "github");
		assert.ok(posture.controls.find((c) => c.id === "vuln").findings.length > 0);
		const cache = await h.waitFor(() => readFile(join(h.home, ARTIFACTS, "radar-cache.json"), "utf8").then(JSON.parse, () => null));
		assert.equal(cache.repo, "acme/widgets");
		assert.doesNotMatch(JSON.stringify(cache), /NEVER-COPY-ME/);
	});
});

test("alert types that are switched off count as empty, but an all-disabled repository is an error", { skip }, async () => {
	const disabled = () => {
		const error = new Error("HTTP 404: Code scanning is not enabled for this repository");
		error.stderr = error.message;
		throw error;
	};
	const live = githubMock();
	const partial = async (command, args, options) => {
		if (args.some((value) => String(value).includes("code-scanning/alerts"))) disabled();
		return live(command, args, options);
	};
	await withExtension({ gh: partial }, async (h) => {
		await synced(h);
		const radar = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(radar.totals.codeScanning, 0);
		assert.equal(radar.totals.dependabot, 1);
		assert.equal(radar.refreshError, null);
	});
	const none = async (command, args, options) => {
		if (args.some((value) => String(value).includes("/alerts"))) disabled();
		return live(command, args, options);
	};
	await withExtension({ gh: none }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "none");
		assert.match(state.refreshError, /Could not sync from GitHub: alerts are not available/);
	});
});

test("uses the cached sync only for the same repository and says when it is stale", { skip }, async () => {
	const cacheFor = (repo) => async (dir) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "radar-cache.json"), JSON.stringify({
			repo, syncedAt: "2024-01-02 03:04",
			code: [codeAlert(1, "js/sql-injection", "src/app.js", 7, "error")], dependabot: [], secrets: [],
		}));
	};
	const offline = async (command, args) => {
		if (args[0] === "repo") return { stdout: "acme/widgets\n" };
		throw new Error("network down");
	};
	await withExtension({ gh: offline, seed: cacheFor("acme/widgets") }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "cache");
		assert.deepEqual(state.findings.map((f) => f.id), ["cs-js-sql-injection"]);
		assert.match(state.refreshError, /Could not reach GitHub \(network down\)\. Showing the last sync from 2024-01-02 03:04\./);
		await assert.rejects(h.invoke("attack-surface-radar", "prepare_campaign", { ids: ["cs-js-sql-injection"], kind: "code" }), /Cached alerts cannot be published/);
	});
	await withExtension({ gh: offline, seed: cacheFor("someone/else") }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "none");
		assert.deepEqual(state.findings, []);
		assert.match(state.refreshError, /Could not sync from GitHub: network down/);
	});
});

test("canvas HTTP actions share isolated launches, assignments and reviewed campaigns without changing scores", { skip }, async () => {
	const publications = [];
	let campaignClosedCount = 2;
	let publicationGate = null;
	let markPublicationStarted;
	const campaignRoutes = async (args) => {
		const path = args.find((value) => value.startsWith("repos/") || value.startsWith("orgs/")) ?? "";
		if (args.includes("POST")) {
			const payload = JSON.parse(await readFile(args[args.indexOf("--input") + 1], "utf8"));
			publications.push(payload);
			markPublicationStarted?.();
			if (publicationGate) await publicationGate;
			return { stdout: JSON.stringify({ number: 9, name: payload.name, description: payload.description, state: "open", ends_at: payload.ends_at,
				alert_stats: { open_count: 8, closed_count: 0, in_progress_count: 2 } }) };
		}
		if (path.includes("/campaigns/9")) return { stdout: JSON.stringify({ number: 9, name: "Campaign test", state: "open",
			alert_stats: { open_count: 8 - campaignClosedCount, closed_count: campaignClosedCount, in_progress_count: 1 } }) };
		return null;
	};
	await withExtension({ gh: githubMock({ handlers: campaignRoutes }) }, async (h) => {
		const { invoke, sent, home, canvases } = h;
		await synced(h);
		for (const canvas of canvases) {
			const instanceId = `test-${canvas.id}`;
			const opened = await canvas.open({ instanceId });
			h.opens.push({ canvas, instanceId });
			assert.equal((await fetch(opened.url)).status, 200);
		}
		assert.equal(h.progressTicks.length, 1);
		await h.progressTicks[0]();
		await setImmediate();
		const radar = await invoke("attack-surface-radar", "get_state", {});
		const round = radar.findings.find((f) => f.id === campaignId(0));
		const local = await invoke("attack-surface-radar", "request_copilot", { id: round.id });
		assert.equal(local.status, "launching");
		for (const { id } of canvases) {
			assert.equal((await invoke(id, "get_state", {})).resetBlocked, true);
			await assert.rejects(invoke(id, "reset_demo", {}), /session launch to finish/);
		}
		assert.match(sent.at(-1).prompt, /workspace_type "worktree"/);
		assert.match(sent.at(-1).prompt, /Do not implement it in this conversation/);
		assert.match(sent.at(-1).prompt, /acme\/widgets/);
		assert.match(sent.at(-1).prompt, /security-radar\//);
		await invoke("attack-surface-radar", "record_fix_session", {
			id: round.id, requestId: local.requestId, sessionId: "fix-child", appUrl: "ghapp://sessions/fix-child",
		});
		const assessmentFinding = radar.findings.find((f) => f.id === campaignId(3));
		const assessmentBefore = { findings: radar.findings, totals: radar.totals, assigned: radar.assigned };
		await invoke("attack-surface-radar", "assess_priority", { id: assessmentFinding.id });
		assert.equal(sent.at(-1).displayPrompt, `Radar · Assess priority: ${assessmentFinding.title}`);
		assert.match(sent.at(-1).prompt, /bounded inspection/);
		assert.match(sent.at(-1).prompt, /read-only inspection/);
		await setImmediate();
		const assessed = await invoke("attack-surface-radar", "get_state", {});
		assert.deepEqual({ findings: assessed.findings, totals: assessed.totals, assigned: assessed.assigned }, assessmentBefore);
		assert.equal(assessed.threads[assessmentFinding.id].at(-1).kind, "assess");
		assert.equal(assessed.threads[assessmentFinding.id].at(-1).status, "done");
		await invoke("attack-surface-radar", "clear_thread", { id: assessmentFinding.id });
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).threads[assessmentFinding.id], undefined);
		assert.equal(assessed.localFixes[round.id].sessionId, "fix-child");
		const count = sent.length;
		await invoke("attack-surface-radar", "request_copilot", { id: round.id });
		assert.equal(sent.length, count, "cross-canvas click must not duplicate the session");
		const other = radar.findings.find((f) => f.id === campaignId(1));
		await invoke("attack-surface-radar", "ask_copilot", { id: other.id, question: "Please fix this locally." });
		assert.match(sent.at(-1).prompt, /Use create_session/);
		assert.match(sent.at(-1).prompt, /Please fix this locally/);
		const posture = await invoke("compliance-scoreboard", "get_state", {});
		const control = posture.controls.find((c) => c.id === "supply");
		const selectedDependency = control.findings.find((f) => f.source === "dependabot");
		assert.equal(selectedDependency.id, "dep-lodash");
		const postureOpen = h.opens.find((o) => o.canvas.id === "compliance-scoreboard");
		const opened = await postureOpen.canvas.open({ instanceId: postureOpen.instanceId });
		const response = await fetch(`${opened.url}api/action`, {
			method: "POST", headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "fix_locally", input: { id: selectedDependency.id, controlId: control.id } }),
		});
		assert.equal(response.status, 200);
		const complianceLocal = await response.json();
		assert.equal(complianceLocal.canvasId, "compliance-scoreboard");
		assert.equal(complianceLocal.id, selectedDependency.id);
		assert.match(sent.at(-1).prompt, new RegExp(selectedDependency.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
		assert.match(sent.at(-1).prompt, /Do not change cloud settings/);
		await invoke("compliance-scoreboard", "ask_copilot", { id: control.id, question: "Please implement the fix." });
		assert.match(sent.at(-1).prompt, /Planning only: do not create sessions/);
		assert.doesNotMatch(sent.at(-1).prompt, /Use create_session/);
		await setImmediate();
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).localFixes[complianceLocal.id].requestId, complianceLocal.requestId);
		await assert.rejects(invoke("compliance-scoreboard", "fix_locally", { id: "secrets" }), /no mapped code or dependency/);
		const secret = radar.findings.find((f) => f.source === "secret-scanning");
		await assert.rejects(invoke("compliance-scoreboard", "fix_locally", { id: secret.id, controlId: "secrets" }), /Secret rotation/);
		await assert.rejects(invoke("compliance-scoreboard", "fix_locally", { id: round.id, controlId: "supply" }), /shown for this control/);
		await assert.rejects(invoke("compliance-scoreboard", "fix_locally", { id: round.id, controlId: "unknown" }), /control themes/);
		await assert.rejects(invoke("attack-surface-radar", "request_copilot", { id: secret.id }), /Secret rotation/);
		const saved = JSON.parse(await readFile(join(home, ARTIFACTS, "local-fixes-test-parent.json"), "utf8"));
		assert.equal(saved[round.id].sessionId, "fix-child");
		assert.equal(saved[other.id].status, "launching");
		const baseline = await invoke("compliance-scoreboard", "get_state", {});
		const localBeforePlanning = structuredClone(baseline.localFixes);
		await invoke("compliance-scoreboard", "draft_dependency_plan", { controlId: "supply", ids: [selectedDependency.id] });
		assert.match(sent.at(-1).prompt, /ONLY the selected dependency groups/);
		assert.match(sent.at(-1).prompt, /NOT a GitHub Security Campaign/);
		await setImmediate();
		for (const ids of [[], [selectedDependency.id, selectedDependency.id], [round.id]]) {
			await assert.rejects(invoke("compliance-scoreboard", "draft_dependency_plan", { controlId: "supply", ids }));
		}
		await assert.rejects(invoke("compliance-scoreboard", "draft_dependency_plan", { controlId: "vuln", ids: [round.id] }), /dependency groups/);
		await invoke("compliance-scoreboard", "draft_evidence", { id: "incident" });
		assert.match(sent.at(-1).prompt, /File presence does not prove response capability/);
		await setImmediate();
		await assert.rejects(invoke("compliance-scoreboard", "draft_evidence", { id: "vuln" }), /incident response evidence/);
		const afterPlanning = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(afterPlanning.score, baseline.score);
		assert.deepEqual(afterPlanning.localFixes, localBeforePlanning);
		assert.equal(afterPlanning.campaigns.draft, null);
		const theme = baseline.controls.find((c) => c.findings.some((f) => f.id === round.id));
		const alert = {
			number: 42, html_url: "https://github.com/acme/widgets/security/code-scanning/42",
			state: "open", rule: { id: round.rule }, assignees: [{ login: "human-owner" }],
			most_recent_instance: { location: { path: round.path, start_line: round.line } },
		};
		const requests = [];
		let releasePatch;
		const patchGate = new Promise((resolve) => { releasePatch = resolve; });
		h.gh = async (command, args) => {
			assert.equal(command, "gh");
			if (args[0] === "repo") return { stdout: "acme/widgets\n" };
			requests.push(args);
			if (args.includes("PATCH")) {
				await patchGate;
				assert.ok(args.includes("repos/acme/widgets/code-scanning/alerts/42"));
				assert.ok(args.includes("assignees[]=human-owner"));
				assert.ok(args.includes("assignees[]=github-agentic-autofix[bot]"));
				alert.assignees.push({ login: "github-agentic-autofix[bot]" });
				return { stdout: JSON.stringify(alert) };
			}
			assert.ok(args.includes("--slurp"));
			assert.ok(args.includes("repos/acme/widgets/code-scanning/alerts?state=open&per_page=100"));
			return { stdout: JSON.stringify([[alert]]) };
		};
		const assigning = invoke("compliance-scoreboard", "assign_copilot", { id: round.id, controlId: theme.id });
		const pending = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(pending.pending.key, theme.id);
		assert.equal(pending.pending.findingId, round.id);
		await assert.rejects(invoke("attack-surface-radar", "reset_demo", {}), /assignment/);
		await assert.rejects(invoke("compliance-scoreboard", "assign_copilot", { id: round.id, controlId: theme.id }), /previous question/);
		releasePatch();
		const result = await assigning;
		assert.equal(result.assigned.number, 42);
		const after = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(after.score, baseline.score);
		assert.equal(after.projected, baseline.projected);
		assert.deepEqual(after.totals, baseline.totals);
		assert.equal(after.pending, null);
		assert.equal(after.threads[theme.id].at(-1).kind, "assign");
		assert.equal(after.threads[theme.id].at(-1).offline, false);
		assert.match(after.threads[theme.id].at(-1).answer, /Assigned alert #42/);
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).assigned[round.id].number, 42);
		await invoke("attack-surface-radar", "assign_copilot", { id: round.id });
		assert.equal(requests.filter((args) => args.includes("PATCH")).length, 1, "already assigned alerts must not be PATCHed again");
		const requestCount = requests.length;
		await assert.rejects(invoke("compliance-scoreboard", "assign_copilot", { id: round.id, controlId: "supply" }), /shown for this control/);
		await assert.rejects(invoke("compliance-scoreboard", "assign_copilot", { id: round.id, controlId: "unknown" }), /control themes/);
		await assert.rejects(invoke("compliance-scoreboard", "assign_copilot", { id: secret.id, controlId: "secrets" }), /Only code scanning/);
		await assert.rejects(invoke("compliance-scoreboard", "assign_copilot", { id: selectedDependency.id, controlId: control.id }), /Only code scanning/);
		assert.equal(requests.length, requestCount, "ineligible actions must not call GitHub");
		h.gh = async (command, args) => {
			if (args[0] === "repo") return { stdout: "acme/widgets\n" };
			throw new Error("GitHub HTTP 403");
		};
		const errorTheme = after.controls.find((c) => c.findings.some((f) => f.id === other.id));
		const failed = await invoke("compliance-scoreboard", "assign_copilot", { id: other.id, controlId: errorTheme.id });
		assert.equal(failed.assigned, null);
		const errorState = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(errorState.pending, null);
		assert.equal(errorState.score, baseline.score);
		assert.equal(errorState.threads[errorTheme.id].at(-1).offline, true);
		assert.match(errorState.threads[errorTheme.id].at(-1).answer, /GitHub HTTP 403/);
		for (const record of Object.values(errorState.localFixes)) {
			if (record.status === "launching") await invoke(record.canvasId, "record_fix_session", {
				id: record.id, requestId: record.requestId,
				sessionId: `child-${record.id}`, appUrl: `ghapp://sessions/child-${record.id}`,
			});
		}
		await invoke("attack-surface-radar", "contain_finding", { id: round.id });
		await invoke("compliance-scoreboard", "preview_lift", {});
		const brief = await invoke("compliance-scoreboard", "generate_brief", {});
		const briefContents = await readFile(brief.path, "utf8");
		assert.match(briefContents, /acme\/widgets/);
		const beforeResetSent = sent.length;
		const beforeResetRequests = requests.length;
		let epoch = errorState.resetEpoch;
		for (const { id } of canvases) {
			const reset = await invoke(id, "reset_demo", {});
			assert.deepEqual(reset, {
				reset: true, scope: "all-security-canvases", sessionsPreserved: true, githubAssignmentsPreserved: true,
			});
			epoch++;
			const radarReset = await invoke("attack-surface-radar", "get_state", {});
			const postureReset = await invoke("compliance-scoreboard", "get_state", {});
			assert.equal(postureReset.resetEpoch, epoch);
			assert.equal(postureReset.resetBlocked, false);
			assert.deepEqual(postureReset.localFixes, {});
			assert.deepEqual(postureReset.threads, {});
			assert.deepEqual(radarReset.threads, {});
			assert.equal(postureReset.preview, false);
			assert.equal(postureReset.brief.open, false);
			assert.equal(postureReset.score, baseline.score);
			assert.equal(radarReset.findings.some((f) => f.contained), false);
			assert.equal(radarReset.assigned[round.id].number, 42);
			assert.equal(postureReset.assigned[round.id].number, 42);
			assert.deepEqual(JSON.parse(await readFile(join(home, ARTIFACTS, "local-fixes-test-parent.json"), "utf8")), {});
			assert.deepEqual(JSON.parse(await readFile(join(home, ARTIFACTS, "state.json"), "utf8")), { contained: [] });
		}
		assert.equal(sent.length, beforeResetSent, "reset must not send commands to existing sessions");
		assert.equal(requests.length, beforeResetRequests, "reset must not change real GitHub assignments");
		assert.equal(await readFile(brief.path, "utf8"), briefContents, "saved brief artifacts must be preserved");
		await assert.rejects(invoke("attack-surface-radar", "record_fix_session", {
			id: round.id, requestId: local.requestId, sessionId: "fix-child", appUrl: "ghapp://sessions/fix-child",
		}), /matching local fix request/);
		const nextFix = await invoke("compliance-scoreboard", "fix_locally", { id: round.id, controlId: theme.id });
		assert.notEqual(nextFix.requestId, local.requestId);
		assert.equal(sent.length, beforeResetSent + 1);
		await invoke("compliance-scoreboard", "record_fix_session", {
			id: round.id, requestId: nextFix.requestId, sessionId: "next-session-child", appUrl: "ghapp://sessions/next-session-child",
		});

		h.gh = githubMock({ handlers: campaignRoutes });
		await invoke("attack-surface-radar", "refresh", {});
		const fresh = await invoke("attack-surface-radar", "get_state", {});
		assert.equal(fresh.source, "github");
		assert.ok(fresh.findings.filter((f) => f.id.startsWith("cs-js-campaign-")).every((f) => f.campaignCount === 1),
			"live branch metadata and stripped refs must reach the campaign model");
		const postureInputs = (await invoke("compliance-scoreboard", "get_state", {})).controls.find((c) => c.id === "vuln").campaignFindings;
		assert.equal(postureInputs.length, 8, "projection must include groups beyond the six-item summary");
		assert.ok(postureInputs.every((f) => f.campaignCount === 1));
		const lastCampaign = campaignId(7);
		const campaignPost = async (name, input) => {
			const reply = await fetch(`${opened.url}api/action`, {
				method: "POST", headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name, input }),
			});
			return { status: reply.status, body: await reply.json() };
		};
		assert.equal((await campaignPost("prepare_campaign", { controlId: "missing", kind: "code" })).status, 400);
		await assert.rejects(invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0), campaignId(0)], kind: "code" }), /distinct/);
		await assert.rejects(invoke("attack-surface-radar", "prepare_campaign", { ids: ["missing"], kind: "code" }), /no longer/);
		const preparedCampaign = await campaignPost("prepare_campaign", { controlId: "vuln", kind: "code" });
		assert.equal(preparedCampaign.status, 200);
		assert.equal(preparedCampaign.body.numbers.length, 8, "theme preparation must not truncate at the six visible groups");
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).controls.find((c) => c.id === "vuln").findings.length, 6);
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).campaigns.draft.id, preparedCampaign.body.id);
		assert.equal(publications.length, 0);
		const review = await campaignPost("review_campaign", {
			id: preparedCampaign.body.id, name: "Campaign test", description: "Fix selected alerts", dueDate: "2099-01-01", manager: "mona",
		});
		assert.equal(review.status, 200);
		assert.equal((await campaignPost("publish_campaign", { id: review.body.id, revision: review.body.revision })).status, 400);
		const scoreBeforePublish = (await invoke("compliance-scoreboard", "get_state", {})).score;
		let releasePublication;
		publicationGate = new Promise((resolve) => { releasePublication = resolve; });
		const publicationStarted = new Promise((resolve) => { markPublicationStarted = resolve; });
		const publishing = invoke("attack-surface-radar", "publish_campaign", { id: review.body.id, revision: review.body.revision, confirm: true });
		await Promise.race([publicationStarted, publishing]);
		assert.equal(publications.length, 1);
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).resetBlocked, true);
		await assert.rejects(invoke("compliance-scoreboard", "reset_demo", {}), /finish/);
		await assert.rejects(invoke("compliance-scoreboard", "publish_campaign", { id: review.body.id, revision: review.body.revision, confirm: true }), /operation to finish/);
		releasePublication();
		await publishing;
		assert.deepEqual(publications[0].code_scanning_alerts, [{ repository_id: 42, alert_numbers: liveCode.map((a) => a.number) }]);
		const campaignState = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(campaignState.score, scoreBeforePublish);
		assert.equal(campaignState.campaigns.receipts[0].campaign.number, 9);
		assert.equal(campaignState.campaigns.receipts[0].campaign.stats.closed_count, 2, "publication automatically refreshes progress");
		campaignClosedCount = 3;
		await invoke("attack-surface-radar", "refresh", {});
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).campaigns.receipts[0].campaign.stats.closed_count, 3,
			"the top Refresh from GitHub action must refresh campaign progress too");
		await invoke("attack-surface-radar", "reset_demo", {});
		await invoke("compliance-scoreboard", "refresh_campaigns", {});
		assert.deepEqual((await invoke("attack-surface-radar", "get_state", {})).campaigns.receipts, [], "Reset forgets real campaign tracking");
		const secretPreparation = await campaignPost("prepare_campaign", { controlId: "secrets", kind: "secrets" });
		assert.equal(secretPreparation.status, 200);
		assert.deepEqual(secretPreparation.body.numbers, [200]);
		assert.doesNotMatch(JSON.stringify(secretPreparation.body), /NEVER-COPY-ME/);
		assert.equal((await campaignPost("publish_campaign", { id: secretPreparation.body.id, confirm: true })).status, 400);
		assert.equal(publications.length, 1, "secrets must use native GitHub finalization");
		await invoke("compliance-scoreboard", "reset_demo", {});
		const campaignLedger = JSON.parse(await readFile(join(home, ARTIFACTS, "campaigns-test-parent.json"), "utf8"));
		assert.equal(campaignLedger.draft, null);
		assert.deepEqual(campaignLedger.receipts, []);
		const radarOpen = await h.opens.find((o) => o.canvas.id === "attack-surface-radar").canvas.open({ instanceId: "test-attack-surface-radar" });
		const direct = await invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" });
		assert.equal(direct.manager, "mona");
		const directInput = { id: direct.id, revision: direct.revision, ids: [campaignId(0)], confirm: true,
			name: "Direct campaign", description: "Fix the selected alert", dueDate: "2099-01-01" };
		const createResponse = await fetch(`${radarOpen.url}api/action`, { method: "POST", headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "create_campaign", input: directInput }) });
		assert.equal(createResponse.status, 200);
		assert.equal((await createResponse.json()).status, "published");
		assert.deepEqual(publications.at(-1).managers, ["mona"]);
		assert.equal(publications.length, 2);
		await assert.rejects(invoke("attack-surface-radar", "create_campaign", directInput), /confirm creation/);
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).score, scoreBeforePublish);
		await invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" });
		const discardResponse = await fetch(`${radarOpen.url}api/action`, { method: "POST", headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "discard_campaign", input: {} }) });
		assert.equal(discardResponse.status, 200, "discard must return JSON success, not fail serializing an undefined result");
		assert.deepEqual(await discardResponse.json(), { discarded: true });
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).campaigns.draft, null);
		assert.equal((await invoke("attack-surface-radar", "get_state", {})).campaigns.receipts.length, 1);
		const mappedState = await invoke("compliance-scoreboard", "get_state", {});
		assert.equal(mappedState.campaignThemes.vuln.length, 8);
		assert.ok(mappedState.campaignThemes.vuln.every((f) => f.title && f.url && f.where));
		await assert.rejects(invoke("compliance-scoreboard", "prepare_campaign", { controlId: "supply", ids: [lastCampaign], kind: "code" }), /control theme/);
		await assert.rejects(invoke("compliance-scoreboard", "prepare_campaign", { controlId: "vuln", ids: [], kind: "code" }), /distinct/);
		await invoke("compliance-scoreboard", "assess_priority", { controlId: "vuln", id: lastCampaign });
		assert.match(sent.at(-1).prompt, /advisory triage, not a compliance assessment/);
		await setImmediate();
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).threads.vuln.at(-1).kind, "assess");
		await assert.rejects(invoke("compliance-scoreboard", "assess_priority", { controlId: "supply", id: lastCampaign }), /control theme/);
		const themeDirect = await invoke("compliance-scoreboard", "prepare_campaign", { controlId: "vuln", ids: [lastCampaign], kind: "code" });
		assert.deepEqual(themeDirect.numbers, [107], "selection is exact, not the entire theme");
		const themeInput = { ...directInput, id: themeDirect.id, revision: themeDirect.revision, ids: [lastCampaign], controlId: "vuln" };
		await assert.rejects(invoke("compliance-scoreboard", "create_campaign", { ...themeInput, controlId: "supply" }), /control theme/);
		const receipt = await invoke("compliance-scoreboard", "create_campaign", themeInput);
		assert.equal(receipt.status, "published");
		assert.equal(receipt.scopeLabel, mappedState.controls.find((c) => c.id === "vuln").title);
		assert.deepEqual(publications.at(-1).code_scanning_alerts, [{ repository_id: 42, alert_numbers: [107] }]);
		assert.deepEqual(publications.at(-1).managers, ["mona"]);
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).score, scoreBeforePublish);
		await import("../extension.mjs?campaign-reload");
		const reloadedRadar = globalThis.canvasTestConfig.canvases.find((c) => c.id === "attack-surface-radar");
		const reloadState = await reloadedRadar.actions.find((a) => a.name === "get_state").handler({ canvasId: reloadedRadar.id, input: {} });
		assert.equal(reloadState.campaigns.receipts[0].campaign.number, 9, "receipts survive provider restart");
	});
});
