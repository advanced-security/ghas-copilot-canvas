import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import * as nodeModule from "node:module";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate, setTimeout as sleep } from "node:timers/promises";
import { findingId, stripAlerts } from "./logic.mjs";

const skip = typeof nodeModule.registerHooks !== "function" && "SDK mocking requires Node 22.15+";
const ARTIFACTS = "extensions/security-radar-nis2/artifacts";
let importSeq = 0;

// Loads extension.mjs against a mocked SDK and a mocked child_process, then hands the helpers to the test body.
async function withExtension({ gh, seed, onImportError }, body) {
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
			if (specifier === "node:fs/promises" && context.parentURL?.includes("/extension.mjs")) {
				return { url: "test:fs-promises", shortCircuit: true };
			}
			if (specifier === "./lib/logic.mjs" && context.parentURL?.includes("/extension.mjs")) {
				return { url: "test:logic", shortCircuit: true };
			}
			if (specifier === "@github/copilot-sdk/extension" || specifier === "node:child_process") {
				return { url: `test:${specifier}`, shortCircuit: true };
			}
			return next(specifier, context);
		},
		load(url, context, next) {
			if (url === "test:fs-promises") return {
				format: "module", shortCircuit: true,
				source: `export * from "node:fs/promises";
					import { rename as original } from "node:fs/promises";
					export async function rename(...args) { await globalThis.canvasTestBeforeRename(...args); return original(...args); }`,
			};
			if (url === "test:logic") return {
				format: "module", shortCircuit: true,
				source: `export * from ${JSON.stringify(new URL("./logic.mjs", import.meta.url).href)};
					import { layoutFindings as original } from ${JSON.stringify(new URL("./logic.mjs", import.meta.url).href)};
					export function layoutFindings(...args) { globalThis.canvasTestLayout(); return original(...args); }`,
			};
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
	const ctx = { gh, home, sent, handlers, opens: [], progressTicks, layoutCalls: 0 };
	globalThis.canvasTestLayout = () => { ctx.layoutCalls++; };
	globalThis.canvasTestBeforeRename = (...args) => ctx.beforeRename?.(...args);
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
		try {
			await import(`../extension.mjs?run-${++importSeq}`);
		} catch (error) {
			await onImportError?.(ctx, error);
			throw error;
		}
		ctx.session = globalThis.canvasTestSession;
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
		delete globalThis.canvasTestLayout;
		delete globalThis.canvasTestBeforeRename;
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
const campaignId = (index) => findingId("cs", `js/campaign-${index}`);
const liveCode = Array.from({ length: 8 }, (_, index) => codeAlert(index + 100, `js/campaign-${index}`, "src/test.js", index + 1));
const workflowAlert = codeAlert(150, "actions/unpinned-tag", ".github/workflows/ci.yml", 12);
const liveSecrets = [{ number: 200, state: "open", secret_type: "provider_key", secret: "NEVER-COPY-ME" }];
const liveDependencies = [{
	number: 300, state: "open", dependency: { package: { name: "lodash", ecosystem: "npm" } }, security_advisory: { severity: "high" },
}];

const ALERT_PROJECTIONS = {
	"code-scanning": ".[] | {number, state, html_url, assignees: [(.assignees // [])[] | {login}], rule: (.rule | {id, severity, security_severity_level, description}), most_recent_instance: (.most_recent_instance | {ref, location: (.location | {path, start_line})})}",
	dependabot: ".[] | {number, state, html_url, dependency: (.dependency | {package: (.package | {ecosystem, name}), manifest_path}), security_advisory: (.security_advisory | {severity})}",
	"secret-scanning": ".[] | {number, state, secret_type, secret_type_display_name, html_url}",
};
const alertLines = (alerts) => alerts.map((alert) => JSON.stringify(alert)).join("\n");

// Answers the gh calls a sync makes. Extra routes can be added through the handlers argument.
function githubMock({ code = [...liveCode, workflowAlert], dependabot = liveDependencies, secrets = liveSecrets, repo = "acme/widgets", handlers } = {}) {
	return async (command, args, options) => {
		assert.equal(command, "gh");
		if (args[0] === "repo") {
			assert.equal(options.cwd, process.cwd(), "repository resolution must use the checkout, not the session artifact directory");
			assert.equal(Object.hasOwn(options.env, "GH_REPO"), false, "checkout discovery must ignore GH_REPO");
			return { stdout: JSON.stringify({ nameWithOwner: repo, url: `https://github.com/${repo}` }) };
		}
		assert.equal(args[args.indexOf("--hostname") + 1], "github.com", "all API calls must target the verified host");
		if (args.includes("--paginate")) assert.equal(options.timeout, 120000, "timeout must cover all sequential pages");
		const path = args.find((value) => value.startsWith("repos/") || value.startsWith("orgs/"));
		const alertType = path?.match(/\/(code-scanning|dependabot|secret-scanning)\/alerts(?:\?|$)/)?.[1];
		if (alertType) {
			assert.ok(args.includes("--paginate"));
			assert.ok(!args.includes("--slurp"));
			assert.equal(args[args.indexOf("--jq") + 1], ALERT_PROJECTIONS[alertType]);
		}
		const custom = await handlers?.(args);
		if (custom) return custom;
		if (args.includes("user")) return { stdout: JSON.stringify({ login: "mona" }) };
		if (path.includes("code-scanning/alerts")) return { stdout: alertLines(code) };
		if (path.includes("secret-scanning/alerts")) {
			assert.ok(args.includes("--paginate"));
			assert.ok(!args.includes("--slurp"));
			assert.equal(args[args.indexOf("--jq") + 1], ".[] | {number, state, secret_type, secret_type_display_name, html_url}");
			return { stdout: secrets.map(({ number, state, secret_type, secret_type_display_name, html_url }) =>
				JSON.stringify({ number, state, secret_type, secret_type_display_name, html_url })).join("\n") };
		}
		if (path.includes("dependabot/alerts")) return { stdout: alertLines(dependabot) };
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
		await assert.rejects(h.invoke("attack-surface-radar", "prepare_campaign", { ids: ["cs-js-campaign-0"], kind: "code" }), /Could not determine/);
		const opened = await h.opens[0].canvas.open({ instanceId: h.opens[0].instanceId });
		assert.equal((await fetch(opened.url)).status, 200);
	});
});

test("reports an unauthenticated gh as an empty state with guidance", { skip }, async () => {
	const gh = async (command, args) => {
		if (args[0] === "repo") return { stdout: JSON.stringify({ nameWithOwner: "acme/widgets", url: "https://github.com/acme/widgets" }) };
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
		assert.ok(ids.includes(findingId("cs", "actions/unpinned-tag")));
		assert.ok(ids.includes(findingId("dep", "npm/lodash")));
		assert.ok(ids.includes(findingId("sec", "provider_key")));
		assert.doesNotMatch(JSON.stringify(radar), /NEVER-COPY-ME/);
		const posture = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.equal(posture.source, "github");
		assert.ok(posture.controls.find((c) => c.id === "vuln").findings.length > 0);
		const cache = await h.waitFor(() => readFile(join(h.home, ARTIFACTS, "radar-cache-acme%2Fwidgets.json"), "utf8").then(JSON.parse, () => null));
		assert.equal(cache.repo, "acme/widgets");
		assert.doesNotMatch(JSON.stringify(cache), /NEVER-COPY-ME/);
		assert.equal((await stat(join(h.home, ARTIFACTS, "radar-cache-acme%2Fwidgets.json"))).mode & 0o777, 0o600);
	});
});

test("non-GitHub origins and gh repository hosts cannot trigger API calls on a namesake repository", { skip }, async () => {
	for (const host of ["gitlab.com", "github.example.com", "github.com.evil.test"]) {
		for (const ghResolves of [true, false]) {
			let apiCalls = 0;
			await withExtension({ gh: async (command, args) => {
				if (command === "git") return { stdout: `https://${host}/acme/widgets.git` };
				if (args[0] === "repo") {
					if (!ghResolves) throw new Error("Repository unavailable");
					return { stdout: JSON.stringify({ nameWithOwner: "acme/widgets", url: `https://${host}/acme/widgets` }) };
				}
				apiCalls++;
				throw new Error("Must not call an API for an unverified host");
			} }, async (h) => {
				const state = await settled(h, (current) => current.refreshError);
				assert.equal(state.repo, null);
				assert.deepEqual(state.findings, []);
				assert.match(state.repoError, /github\.com origin/);
				await assert.rejects(h.invoke("attack-surface-radar", "assign_copilot", { id: campaignId(0) }), /Could not determine/);
				assert.equal(apiCalls, 0);
			});
		}
	}
});

test("assignments serialize both canvases and refresh from repository admission through PATCH completion", { skip }, async () => {
	for (const canvas of ["attack-surface-radar", "compliance-scoreboard"]) {
		for (const stage of ["resolution", "patch"]) {
			await withExtension({ gh: githubMock() }, async (h) => {
				await synced(h);
				const other = canvas === "attack-surface-radar" ? "compliance-scoreboard" : "attack-surface-radar";
				const input = { id: campaignId(0), ...(canvas === "compliance-scoreboard" ? { controlId: "vuln" } : {}) };
				const { promise, resolve } = Promise.withResolvers();
				let entered = false;
				let assigned = false;
				let patches = 0;
				const live = githubMock({ handlers: async (args) => {
					if (args.includes("PATCH")) {
						patches++;
						if (stage === "patch") { entered = true; await promise; }
						assigned = true;
						return { stdout: JSON.stringify({ assignees: [{ login: "copilot" }] }) };
					}
					if (assigned && args.some((arg) => arg.includes("code-scanning/alerts"))) {
						return { stdout: alertLines(liveCode.map((alert) =>
							({ ...alert, assignees: [{ login: "copilot" }] }))) };
					}
				} });
				h.gh = async (command, args, options) => {
					if (stage === "resolution" && args[0] === "repo") { entered = true; await promise; }
					return live(command, args, options);
				};
				const pending = h.invoke(canvas, "assign_copilot", input);
				try {
					await h.waitFor(() => entered);
					await assert.rejects(h.invoke(other, "assign_copilot", { id: input.id, controlId: "vuln" }), /current GitHub operation/);
					for (const target of [canvas, other]) {
						await assert.rejects(h.invoke(target, "refresh", {}), /current GitHub operation/);
					}
					await assert.rejects(h.invoke(other, "reset_demo", {}), /finish/);
					if (stage === "patch") await assert.rejects(h.invoke(other, "ask_copilot", {
						id: other === "attack-surface-radar" ? input.id : "vuln", question: "Explain the risk",
					}), /previous question/);
				} finally {
					resolve();
					await pending;
				}
				assert.equal(patches, 1);
				for (const target of [canvas, other]) {
					assert.equal((await h.invoke(target, "get_state", {})).assigned[input.id].number, 100);
				}
				await h.invoke(other, "refresh", {});
				const refreshed = await h.invoke("attack-surface-radar", "get_state", {});
				assert.equal(refreshed.findings.find((finding) => finding.id === input.id).copilot.number, 100);
			});
		}
	}
});

test("refresh admission blocks assignments before asynchronous repository resolution finishes", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const live = githubMock();
		const { promise, resolve } = Promise.withResolvers();
		let entered = false;
		h.gh = async (command, args, options) => {
			if (args[0] === "repo") { entered = true; await promise; }
			return live(command, args, options);
		};
		const refresh = h.invoke("attack-surface-radar", "refresh", {});
		try {
			await h.waitFor(() => entered);
			for (const canvas of ["attack-surface-radar", "compliance-scoreboard"]) {
				await assert.rejects(h.invoke(canvas, "assign_copilot", { id: campaignId(0), controlId: "vuln" }), /current GitHub operation/);
			}
		} finally {
			resolve();
			await refresh;
		}
		h.gh = async (command, args, options) => {
			if (args.includes("PATCH")) throw new Error("GitHub HTTP 403");
			return live(command, args, options);
		};
		const result = await h.invoke("attack-surface-radar", "assign_copilot", { id: campaignId(0) });
		assert.equal(result.assigned, null);
		await h.invoke("compliance-scoreboard", "refresh", {});
		assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).resetBlocked, false);
	});
});

test("a corrupt or unreadable fix-session ledger fails initialization before any launch or refresh", { skip }, async () => {
	for (const saved of ["{broken", "[]", '{"saved":{"requestId":"old"}}', null]) {
		let calls = 0;
		await assert.rejects(withExtension({
			gh: async () => { calls++; throw new Error("No API calls expected"); },
			seed: async (dir) => {
				await mkdir(dir, { recursive: true });
				const path = join(dir, "local-fixes-test-parent.json");
				if (saved === null) await mkdir(path);
				else await writeFile(path, saved);
			},
		}, () => assert.fail("extension must not initialize with a lost deduplication ledger")), /Cannot safely restore dedicated fix sessions/);
		assert.equal(calls, 0);
	}
});

test("all repository-dependent actions exclude refresh while their discovery result is pending", { skip }, async () => {
	const actions = [
		["attack-surface-radar", "explain_finding", { id: campaignId(0) }],
		["attack-surface-radar", "ask_copilot", { id: campaignId(0), question: "Explain the risk" }],
		["attack-surface-radar", "request_copilot", { id: campaignId(0) }],
		["attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" }],
		["compliance-scoreboard", "draft_dependency_plan", { controlId: "supply", ids: [findingId("dep", "npm/lodash")] }],
		["compliance-scoreboard", "generate_brief", {}],
	];
	for (const [canvas, name, input] of actions) {
		await withExtension({ gh: githubMock() }, async (h) => {
			await synced(h);
			const { promise, resolve } = Promise.withResolvers();
			let entered = false;
			let resolutions = 0;
			const original = githubMock();
			h.gh = async (command, args, options) => {
				if (args[0] === "repo") { resolutions++; entered = true; await promise; }
				return original(command, args, options);
			};
			const action = h.invoke(canvas, name, input);
			try {
				await h.waitFor(() => entered);
				for (const target of ["attack-surface-radar", "compliance-scoreboard"]) {
					await assert.rejects(h.invoke(target, "refresh", {}), /current GitHub operation/);
					await assert.rejects(h.invoke(target, "ask_copilot", {
						id: target === "attack-surface-radar" ? campaignId(0) : "vuln", question: "Explain the risk",
					}), /current GitHub operation/);
				}
				assert.equal(resolutions, 1, `${name}: rejected actions must not start another discovery`);
			} finally {
				resolve();
				await action;
			}
			h.gh = githubMock({ repo: "acme/second", code: [{
				...codeAlert(999, "js/second", "new.js", 1), html_url: "https://github.com/acme/second/security/code-scanning/999",
			}] });
			await h.invoke("attack-surface-radar", "refresh", {});
			const state = await h.invoke("attack-surface-radar", "get_state", {});
			assert.equal(state.repo, "acme/second");
			assert.equal(state.findings.find((finding) => finding.source === "code-scanning").rule, "js/second");
			assert.ok(state.findings.every((finding) => finding.url.includes("/acme/second/")));
		});
	}
});

test("an action cannot resolve an old repository while a new repository refresh is fetching alerts", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const { promise, resolve } = Promise.withResolvers();
		let entered = false;
		let resolutions = 0;
		const next = githubMock({ repo: "acme/second", code: [codeAlert(999, "js/second", "new.js", 1)] });
		h.gh = async (command, args, options) => {
			if (args[0] === "repo") resolutions++;
			if (args.some((arg) => arg.includes("/code-scanning/alerts"))) { entered = true; await promise; }
			return next(command, args, options);
		};
		const refresh = h.invoke("compliance-scoreboard", "refresh", {});
		try {
			await h.waitFor(() => entered);
			await assert.rejects(h.invoke("attack-surface-radar", "ask_copilot", {
				id: campaignId(0), question: "Explain this",
			}), /current GitHub operation/);
			assert.equal(resolutions, 1);
		} finally {
			resolve();
			await refresh;
		}
		const state = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(state.repo, "acme/second");
		assert.equal(state.findings.find((finding) => finding.source === "code-scanning").rule, "js/second");
	});
});

test("GH_REPO cannot override the checkout used for repository discovery", { skip }, async () => {
	const previous = process.env.GH_REPO;
	process.env.GH_REPO = "someone/else";
	try {
		await withExtension({ gh: githubMock() }, async (h) => {
			const radar = await synced(h);
			assert.equal(radar.repo, "acme/widgets");
			assert.equal(process.env.GH_REPO, "someone/else", "do not mutate the parent environment");
			await h.invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" });
			assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).campaigns.draft.repo, "acme/widgets");
		});
	} finally {
		if (previous === undefined) delete process.env.GH_REPO;
		else process.env.GH_REPO = previous;
	}
});

test("invalid campaign ledgers fail initialization without replacing receipts or querying placeholder repositories", { skip }, async () => {
	for (const saved of ["{broken", '{"receipts":[{"id":"keep-me","repo":"invalid"}]}', '{"receipts":[],"draft":{"repo":null}}']) {
		let calls = 0;
		await assert.rejects(withExtension({
			gh: async () => { calls++; throw new Error("No GitHub calls expected"); },
			seed: async (dir) => {
				await mkdir(dir, { recursive: true });
				await writeFile(join(dir, "campaigns-test-parent.json"), saved);
			},
			onImportError: async (h) => {
				assert.equal(await readFile(join(h.home, ARTIFACTS, "campaigns-test-parent.json"), "utf8"), saved);
				assert.equal(h.progressTicks.length, 0);
			},
		}, () => assert.fail("corrupt receipts must prevent initialization")), /Cannot safely restore campaign receipts/);
		assert.equal(calls, 0);
	}
});

test("radar layout is cached across state reads, annotations and answer events but invalidated by fresh findings", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		const state = await synced(h);
		const calls = h.layoutCalls;
		for (let i = 0; i < 5; i++) await h.invoke("attack-surface-radar", "get_state", {});
		await h.invoke("attack-surface-radar", "contain_finding", { id: campaignId(0) });
		const annotated = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(annotated.findings.find((finding) => finding.id === campaignId(0)).contained, true);
		await h.invoke("attack-surface-radar", "explain_finding", { id: campaignId(0) });
		await settled(h, (current) => !current.pending);
		assert.equal(h.layoutCalls, calls, "non-layout state updates must not recompute pairwise layout");
		await h.invoke("attack-surface-radar", "refresh", {});
		const fresh = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(h.layoutCalls, calls + 1);
		assert.notEqual(fresh.layoutSeed, state.layoutSeed);
		await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(h.layoutCalls, calls + 1);
	});
});

test("default local fixes skip secret groups and explicit secret selection remains rejected", { skip }, async () => {
	await withExtension({ gh: githubMock({ code: [], secrets: liveSecrets }) }, async (h) => {
		const state = await synced(h);
		const secret = state.findings.find((finding) => finding.source === "secret-scanning");
		assert.equal(state.findings[0].source, "secret-scanning");
		const launch = await h.invoke("attack-surface-radar", "request_copilot", {});
		assert.equal(launch.id, findingId("dep", "npm/lodash"));
		assert.equal(h.sent.length, 1);
		await assert.rejects(h.invoke("attack-surface-radar", "request_copilot", { id: secret.id }), /Secret rotation/);
		assert.equal(h.sent.length, 1);
	});
	await withExtension({ gh: githubMock({ code: [], dependabot: [] }) }, async (h) => {
		await synced(h);
		await assert.rejects(h.invoke("attack-surface-radar", "request_copilot", {}), /No uncontained non-secret/);
		assert.equal(h.sent.length, 0);
	});
});

test("brief generations keep unique immutable paths across snapshots and repository changes", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const first = await h.invoke("compliance-scoreboard", "generate_brief", {});
		const contents = await readFile(first.path, "utf8");
		const posture = h.canvases.find((canvas) => canvas.id === "compliance-scoreboard");
		const opened = await posture.open({ instanceId: "brief-render-check" });
		h.opens.push({ canvas: posture, instanceId: "brief-render-check" });
		const page = await (await fetch(opened.url)).text();
		assert.doesNotMatch(page, /saved as audit-brief\.md/);
		const second = await h.invoke("compliance-scoreboard", "generate_brief", {});
		assert.notEqual(first.path, second.path);
		assert.equal(await readFile(first.path, "utf8"), contents);
		h.gh = githubMock({ repo: "acme/second" });
		await h.invoke("attack-surface-radar", "refresh", {});
		const third = await h.invoke("compliance-scoreboard", "generate_brief", {});
		assert.notEqual(second.path, third.path);
		assert.match(await readFile(third.path, "utf8"), /acme\/second/);
		assert.equal(await readFile(first.path, "utf8"), contents);
		assert.match(contents, /acme\/widgets/);
		assert.equal((await h.invoke("compliance-scoreboard", "get_state", {})).brief.path, third.path);
		for (const brief of [first, second, third]) assert.equal((await stat(brief.path)).mode & 0o777, 0o600);
	});
});

test("events in the same batch cannot overwrite a completed panel answer", { skip }, async () => {
	for (const tail of ["assistant", "user"]) {
		await withExtension({ gh: githubMock() }, async (h) => {
			await synced(h);
			const emit = (type, content) => {
				for (const handler of h.handlers.get(type) ?? []) handler({ data: { content } });
			};
			h.session.send = async (message) => {
				emit("user.message", message.prompt);
				emit("assistant.message", "The completed panel answer.");
				if (tail === "assistant") emit("assistant.message", "Unrelated chat answer.");
				else emit("user.message", "A different chat question.");
			};
			await h.invoke("attack-surface-radar", "ask_copilot", { id: campaignId(0), question: "Explain the risk" });
			const state = await settled(h, (current) => !current.pending);
			const entry = state.threads[campaignId(0)].at(-1);
			assert.equal(entry.answer, "The completed panel answer.");
			assert.equal(entry.offline, false);
		});
	}
});

test("mixed-case restored repositories preserve offline cache, draft visibility and fix-session deduplication", { skip }, async () => {
	const id = campaignId(0);
	let online = true;
	const live = githubMock({ repo: "Acme/Widgets" });
	await withExtension({
		gh: (command, args, options) => {
			if (!online) {
				if (command === "git") return { stdout: "git@github.com:acme/widgets.git" };
				throw new Error("Offline");
			}
			return live(command, args, options);
		},
		seed: async (dir) => {
			await mkdir(dir, { recursive: true });
			await writeFile(join(dir, "local-fixes-test-parent.json"), JSON.stringify({
				[id]: { id, requestId: "saved", canvasId: "attack-surface-radar", status: "unknown", repo: "Acme/Widgets" },
			}));
			await writeFile(join(dir, "campaigns-test-parent.json"), JSON.stringify({
				draft: { id: "saved-draft", repo: "ACME/WIDGETS" }, receipts: [],
			}));
		},
	}, async (h) => {
		const initial = await synced(h);
		assert.equal(initial.repo, "acme/widgets");
		assert.equal(initial.localFixes[id].requestId, "saved");
		assert.equal(initial.campaigns.draft.id, "saved-draft");
		const dir = join(h.home, ARTIFACTS);
		const cacheFile = join(dir, "radar-cache-acme%2Fwidgets.json");
		const cache = JSON.parse(await readFile(cacheFile, "utf8"));
		cache.repo = "Acme/Widgets";
		await writeFile(cacheFile, JSON.stringify(cache));
		online = false;
		// Reload so fallback must restore the uppercase payload rather than retain in-memory data.
		await import(`../extension.mjs?case-reload-${++importSeq}`);
		const canvas = globalThis.canvasTestConfig.canvases.find((item) => item.id === "attack-surface-radar");
		const invoke = (name, input = {}) => canvas.actions.find((action) => action.name === name).handler({ canvasId: canvas.id, input });
		await h.waitFor(async () => !(await invoke("get_state")).refreshing);
		const restored = await invoke("get_state");
		assert.equal(restored.repo, "acme/widgets");
		assert.equal(restored.source, "cache");
		assert.equal(restored.campaigns.draft.id, "saved-draft");
		assert.equal(restored.localFixes[id].repo, "acme/widgets");
		await invoke("request_copilot", { id });
		assert.equal(h.sent.length, 0, "existing unknown receipt must be reused after case-only fallback");
		await invoke("reset_demo");
		const reset = await invoke("get_state");
		assert.equal(reset.localFixes[id].status, "unknown");
		await invoke("record_fix_session", { id, requestId: "saved", sessionId: "late-child", appUrl: "ghapp://sessions/late-child" });
		assert.equal((await invoke("get_state")).localFixes[id].status, "launched");
	});
});

test("containment annotations are repository-scoped and cannot change live posture or campaign scope", { skip }, async () => {
	const id = campaignId(0);
	const seed = async (dir) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "state.json"), JSON.stringify({ contained: [id] }));
		await writeFile(join(dir, "state-someone%2Felse.json"), JSON.stringify({ repo: "someone/else", contained: [id] }));
	};
	let saved;
	await withExtension({ gh: githubMock(), seed }, async (h) => {
		const radar = await synced(h);
		assert.equal(radar.findings.some((finding) => finding.contained), false, "ignore legacy and other-repository state");
		const baseline = await h.invoke("compliance-scoreboard", "get_state", {});
		await h.invoke("attack-surface-radar", "contain_finding", { id });
		assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).findings.find((finding) => finding.id === id).contained, true);
		const annotated = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.deepEqual(annotated.controls, baseline.controls);
		assert.deepEqual(annotated.campaignThemes, baseline.campaignThemes);
		assert.equal(annotated.score, baseline.score);
		assert.equal(annotated.projected, baseline.projected);
		const dependency = radar.findings.find((finding) => finding.source === "dependabot");
		await h.invoke("attack-surface-radar", "contain_finding", { id: dependency.id });
		await h.invoke("compliance-scoreboard", "draft_dependency_plan", { controlId: "supply", ids: [dependency.id] });
		await h.waitFor(async () => !(await h.invoke("compliance-scoreboard", "get_state", {})).pending);
		assert.match(h.sent.at(-1).prompt, /lodash/);
		assert.equal((await h.invoke("compliance-scoreboard", "get_state", {})).score, baseline.score);
		await h.invoke("attack-surface-radar", "reset_contains", {});
		await h.invoke("attack-surface-radar", "contain_finding", { id });
		saved = await readFile(join(h.home, ARTIFACTS, "state-acme%2Fwidgets.json"), "utf8");
		assert.deepEqual(JSON.parse(saved), { repo: "acme/widgets", contained: [id] });
	});
	for (const repo of ["acme/widgets", "someone/else"]) {
		await withExtension({
			gh: githubMock({ repo }),
			seed: async (dir) => {
				await mkdir(dir, { recursive: true });
				await writeFile(join(dir, "state-acme%2Fwidgets.json"), saved);
			},
		}, async (h) => {
			const state = await synced(h);
			assert.equal(state.findings.find((finding) => finding.id === id).contained, repo === "acme/widgets");
		});
	}
});

test("existing permissive caches become owner-only on offline restore and live replacement", { skip }, async () => {
	for (const offline of [false, true]) {
		const live = githubMock();
		await withExtension({
			gh: (command, args, options) => {
				if (offline && args[0] !== "repo") throw new Error("network down");
				return live(command, args, options);
			},
			seed: async (dir) => {
				await mkdir(dir, { recursive: true });
				await writeFile(join(dir, "radar-cache-acme%2Fwidgets.json"), JSON.stringify({
					repo: "acme/widgets", code: liveCode, dependabot: [], secrets: [], syncedAt: "yesterday",
				}), { mode: 0o644 });
			},
		}, async (h) => {
			await settled(h, (state) => offline ? state.refreshError : state.source === "github");
			assert.equal((await stat(join(h.home, ARTIFACTS, "radar-cache-acme%2Fwidgets.json"))).mode & 0o777, 0o600);
		});
	}
});

test("panel asks are serialized across both canvases and release the shared guard after failure", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const emit = (type, data) => {
			for (const handler of h.handlers.get(type) ?? []) handler({ data });
		};
		h.session.send = async (message) => { h.sent.push(message); };
		for (const first of ["attack-surface-radar", "compliance-scoreboard"]) {
			const other = first === "attack-surface-radar" ? "compliance-scoreboard" : "attack-surface-radar";
			const input = (canvas) => ({ id: canvas === "attack-surface-radar" ? campaignId(0) : "vuln", question: "Explain the risk" });
			await h.invoke(first, "ask_copilot", input(first));
			const count = h.sent.length;
			await assert.rejects(h.invoke(other, "ask_copilot", input(other)), /previous question/);
			assert.equal(h.sent.length, count, "a rejected ask must not send an interleaving prompt");
			emit("user.message", { content: h.sent.at(-1).prompt });
			emit("assistant.message", { content: `Answer for ${first}` });
			await h.waitFor(async () => !(await h.invoke(first, "get_state", {})).pending);
			const entry = (await h.invoke(first, "get_state", {})).threads[input(first).id].at(-1);
			assert.equal(entry.answer, `Answer for ${first}`);
			assert.equal(entry.offline, false);
		}
		h.session.send = async () => { throw new Error("send unavailable"); };
		await h.invoke("attack-surface-radar", "explain_finding", { id: campaignId(0) });
		await settled(h, (state) => !state.pending);
		h.session.send = async (message) => { h.sent.push(message); };
		await h.invoke("compliance-scoreboard", "draft_plan", { id: "vuln" });
		emit("user.message", { content: h.sent.at(-1).prompt });
		emit("assistant.message", { content: "Recovered answer" });
		await h.waitFor(async () => !(await h.invoke("compliance-scoreboard", "get_state", {})).pending);
	});
});

test("read-only Git questions stay in the panel and unsafe alert attachments are rejected before sending", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		for (const question of ["Which branch contains this alert?", "What commit introduced it?", "Please review this PR",
			"Please don't fix this; just explain the risk", "Ne corrige pas ça", "Please discuss whether to fix this"]) {
			await h.invoke("attack-surface-radar", "ask_copilot", { id: campaignId(0), question });
			await settled(h, (state) => !state.pending);
			assert.doesNotMatch(h.sent.at(-1).prompt, /Use create_session/);
			assert.deepEqual((await h.invoke("attack-surface-radar", "get_state", {})).localFixes, {});
		}
	});
	await withExtension({ gh: githubMock({ code: [codeAlert(1, "unsafe/path", "../outside.js", 2)] }) }, async (h) => {
		const state = await synced(h);
		await assert.rejects(h.invoke("attack-surface-radar", "explain_finding", { id: state.findings.find((finding) => finding.source === "code-scanning").id }), /must stay inside the repository/);
		assert.equal(h.sent.length, 0);
		assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).pending, null);
	});
});

test("canvas HTTP routes require instance capabilities, exact Host and Origin, and same-origin JSON actions", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const canvas = h.canvases.find((item) => item.id === "attack-surface-radar");
		const opened = await canvas.open({ instanceId: "test-attack-surface-radar" });
		const { origin, pathname } = new URL(opened.url);
		assert.match(pathname, /^\/[0-9a-f]{64}\/$/);
		for (const route of ["", "api/state", "events", "api/action"]) {
			const method = route === "api/action" ? "POST" : "GET";
			assert.equal((await fetch(`${origin}/${route}`, { method })).status, 403, "missing token");
			assert.equal((await fetch(`${opened.url}${route}`, { method, headers: { Origin: "https://attacker.example" } })).status, 403, "foreign origin");
			const status = await new Promise((resolve, reject) => {
				const req = request(`${opened.url}${route}`, { method, headers: { Host: "attacker.example" } }, (res) => {
					res.resume();
					resolve(res.statusCode);
				});
				req.on("error", reject);
				req.end();
			});
			assert.equal(status, 403, "DNS rebinding");
		}
		const actionUrl = `${opened.url}api/action`;
		const body = JSON.stringify({ name: "request_copilot", input: { id: campaignId(0) } });
		for (const headers of [
			{ "Content-Type": "text/plain", Origin: origin },
			{ "Content-Type": "application/json" },
			{ "Content-Type": "application/json", Origin: "null" },
		]) {
			assert.equal((await fetch(actionUrl, { method: "POST", headers, body })).status, 403);
		}
		assert.equal(h.sent.length, 0);
		for (const route of ["", "api/state"]) {
			const response = await fetch(`${opened.url}${route}`);
			assert.equal(response.status, 200);
			assert.equal(response.headers.get("referrer-policy"), "no-referrer");
			if (!route) {
				const html = await response.text();
				assert.match(html, /fetch\("api\/action"/);
				assert.match(html, /new EventSource\("events"\)/);
			}
		}
		const stream = await fetch(`${opened.url}events`);
		assert.equal(stream.status, 200);
		const reader = stream.body.getReader();
		assert.match(new TextDecoder().decode((await reader.read()).value), /^data: /);
		await reader.cancel();
		const headers = { "Content-Type": "application/json", Origin: origin };
		assert.equal((await fetch(actionUrl, { method: "POST", headers, body: JSON.stringify({ name: "get_state" }) })).status, 200);
		assert.equal((await fetch(actionUrl, { method: "POST", headers, body: JSON.stringify({ name: "request_copilot", repo: "wrong/repo", input: { id: campaignId(0) } }) })).status, 400);
		const other = await canvas.open({ instanceId: "capability-other" });
		h.opens.push({ canvas, instanceId: "capability-other" });
		assert.equal((await fetch(`${new URL(other.url).origin}${pathname}api/state`)).status, 403, "capabilities are instance-specific");
		assert.notEqual(new URL(other.url).pathname, pathname);
		assert.equal(h.sent.length, 0);
	});
});

test("explicit stale local-fix IDs never fall back to another alert", { skip }, async () => {
	await withExtension({ gh: githubMock({ code: [codeAlert(1, "js/default-fix", "src/app.js", 2, "error")] }) }, async (h) => {
		await synced(h);
		for (const id of ["removed-rule", "", null, 12]) {
			await assert.rejects(h.invoke("attack-surface-radar", "request_copilot", { id }), /no longer on the radar/);
		}
		assert.equal(h.sent.length, 0);
		const launched = await h.invoke("attack-surface-radar", "request_copilot", {});
		assert.equal(launched.status, "launching");
		assert.equal(h.sent.length, 1);
	});
});

test("briefs and local-fix ledgers tighten pre-existing permissive files", { skip }, async () => {
	await withExtension({
		gh: githubMock(),
		seed: async (dir) => {
			await mkdir(dir, { recursive: true });
			await writeFile(join(dir, "audit-brief.md"), "old brief", { mode: 0o644 });
			await writeFile(join(dir, "local-fixes-test-parent.json"), "{}", { mode: 0o644 });
			await writeFile(join(dir, "local-fixes-test-parent.json.tmp"), "{}", { mode: 0o644 });
		},
	}, async (h) => {
		await synced(h);
		const dir = join(h.home, ARTIFACTS);
		assert.equal((await stat(join(dir, "local-fixes-test-parent.json"))).mode & 0o777, 0o600);
		const brief = await h.invoke("compliance-scoreboard", "generate_brief", {});
		assert.equal((await stat(brief.path)).mode & 0o777, 0o600);
		assert.match(await readFile(brief.path, "utf8"), /acme\/widgets/);
		await h.invoke("attack-surface-radar", "request_copilot", { id: campaignId(0) });
		assert.equal((await stat(join(dir, "local-fixes-test-parent.json"))).mode & 0o777, 0o600);
	});
});

test("repository switches clear old alerts and evidence, preserve receipts and keep independent offline caches", { skip }, async () => {
	let repo = "acme/widgets";
	let offline = false;
	let settingsReadable = true;
	const gh = (command, args, options) => {
		if (args[0] !== "repo" && offline) throw new Error("network down");
		if (args.includes("--jq") && !args.includes("--paginate") && !settingsReadable) throw new Error("settings unreadable");
		return githubMock({
			repo,
			handlers: async (request) => {
				if (request.includes("--jq") && !request.includes("--paginate")) return { stdout: JSON.stringify({
					default_branch: "main", secret_scanning_push_protection: { status: "enabled" },
				}) };
			},
		})(command, args, options);
	};
	await withExtension({
		gh,
		seed: async (dir) => {
			await mkdir(dir, { recursive: true });
			await writeFile(join(dir, "campaigns-test-parent.json"), JSON.stringify({
				draft: null, receipts: [{ id: "unconfirmed", repo: "acme/widgets", marker: "[canvas:unconfirmed]", status: "unknown" }],
			}));
		},
	}, async (h) => {
		await synced(h);
		const a = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.equal(a.controls.find((control) => control.id === "secrets").evidence.find((item) => item.id === "push-protection").status, true);
		await h.invoke("attack-surface-radar", "request_copilot", { id: campaignId(0) });
		const ledgerPath = join(h.home, ARTIFACTS, "local-fixes-test-parent.json");
		const ledger = await readFile(ledgerPath, "utf8");
		repo = "acme/second";
		offline = true;
		await assert.rejects(h.invoke("attack-surface-radar", "request_copilot", { id: campaignId(0) }), /Repository changed/);
		await h.invoke("attack-surface-radar", "refresh", {});
		const bOffline = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(bOffline.repo, repo);
		assert.equal(bOffline.source, "none");
		assert.deepEqual(bOffline.findings, []);
		assert.equal(bOffline.totals.codeScanning, 0);
		assert.deepEqual(bOffline.assigned, {});
		assert.deepEqual(bOffline.localFixes, {});
		assert.equal(bOffline.campaigns.receipts[0].status, "unknown");
		assert.equal(await readFile(ledgerPath, "utf8"), ledger, "unconfirmed launch records are preserved");
		assert.equal(h.sent.length, 1, "stale action must not launch a session");
		offline = false;
		settingsReadable = false;
		await h.invoke("attack-surface-radar", "refresh", {});
		const b = await h.invoke("compliance-scoreboard", "get_state", {});
		assert.equal(b.source, "github");
		assert.equal(b.controls.find((control) => control.id === "secrets").evidence.find((item) => item.id === "push-protection").status, null);
		const dir = join(h.home, ARTIFACTS);
		const aCache = JSON.parse(await readFile(join(dir, "radar-cache-acme%2Fwidgets.json"), "utf8"));
		const bCache = JSON.parse(await readFile(join(dir, "radar-cache-acme%2Fsecond.json"), "utf8"));
		assert.equal(aCache.settings.secret_scanning_push_protection.status, "enabled");
		assert.equal(bCache.settings, null);
		await assert.rejects(h.invoke("attack-surface-radar", "request_copilot", { id: campaignId(0) }), /belongs to another repository/);
		repo = "acme/widgets";
		offline = true;
		await h.invoke("attack-surface-radar", "refresh", {});
		const restored = await h.invoke("attack-surface-radar", "get_state", {});
		assert.equal(restored.source, "cache");
		assert.ok(restored.findings.length > 0);
		assert.equal(restored.localFixes[campaignId(0)].status, "launching");
		repo = "acme/second";
		await h.invoke("attack-surface-radar", "refresh", {});
		assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).source, "cache");
	});
});

test("secret sync and campaign preparation parse only projected metadata over multiple pages", { skip }, async () => {
	const secrets = [{ number: 11, state: "open", secret_type: "provider_key" }, { number: 12, state: "open", secret_type: "provider_key" }];
	let projectedCalls = 0;
	const gh = githubMock({ secrets, handlers: async (args) => {
		if (!args.some((arg) => arg.includes("/secret-scanning/alerts"))) return;
		assert.ok(args.includes("--paginate"));
		assert.ok(!args.includes("--slurp"));
		assert.equal(args[args.indexOf("--jq") + 1], ".[] | {number, state, secret_type, secret_type_display_name, html_url}");
		projectedCalls++;
		return { stdout: secrets.map((alert) => JSON.stringify(alert)).join("\n") + "\n" };
	} });
	await withExtension({ gh }, async (h) => {
		const radar = await synced(h);
		assert.equal(radar.totals.secretScanning, 2);
		const finding = radar.findings.find((item) => item.source === "secret-scanning");
		const draft = await h.invoke("attack-surface-radar", "prepare_campaign", { ids: [finding.id], kind: "secrets" });
		assert.deepEqual(draft.numbers, [11, 12]);
		assert.equal(projectedCalls, 2, "both alert sync and campaign selection use boundary projection");
	});
});

test("large code and dependency listings project before buffering and retain campaign and assignment metadata", { skip }, async () => {
	const description = "x".repeat(5000);
	const code = Array.from({ length: 4000 }, (_, i) => ({
		...codeAlert(i + 1, `js/large-${i % 4}`, "src/large.js", i + 1),
		assignees: [{ login: i === 0 ? "copilot" : "human-owner", avatar_url: description }],
		most_recent_instance: {
			ref: i % 8 < 4 ? "refs/heads/main" : "refs/heads/feature",
			location: { path: "src/large.js", start_line: i + 1, snippet: description },
		},
	}));
	const dependabot = Array.from({ length: 4000 }, (_, i) => ({
		number: i + 1, state: "open", html_url: `https://github.com/acme/widgets/security/dependabot/${i + 1}`,
		dependency: { package: { ecosystem: "npm", name: `package-${i % 4}` }, manifest_path: "package-lock.json" },
		security_advisory: { severity: "high", description },
	}));
	const limit = 16 * 1024 * 1024;
	for (const alerts of [code, dependabot]) assert.ok(Buffer.byteLength(JSON.stringify(alerts)) > limit);
	const stripped = stripAlerts({ code, dependabot });
	const projected = {
		"code-scanning": stripped.code.map((alert, i) => ({ ...alert, state: code[i].state })),
		dependabot: stripped.dependabot.map((alert, i) => ({ ...alert, state: dependabot[i].state })),
	};
	let calls = 0;
	const gh = githubMock({ handlers: async (args) => {
		const path = args.find((arg) => arg.startsWith("repos/"));
		const type = path?.match(/\/(code-scanning|dependabot)\/alerts\?/)?.[1];
		if (!type) return;
		assert.equal(args[args.indexOf("--jq") + 1], ALERT_PROJECTIONS[type]);
		const stdout = alertLines(projected[type]) + "\n";
		assert.ok(Buffer.byteLength(stdout) < limit);
		assert.ok(!stdout.includes(description));
		calls++;
		return { stdout };
	} });
	await withExtension({ gh }, async (h) => {
		const state = await synced(h);
		assert.equal(state.totals.codeScanning, 4000);
		assert.equal(state.totals.dependabot, 4000);
		const finding = state.findings.find((item) => item.rule === "js/large-0");
		assert.equal(finding.count, 1000);
		assert.equal(finding.copilot.number, 1);
		assert.equal(finding.path, "src/large.js");
		const draft = await h.invoke("attack-surface-radar", "prepare_campaign", { ids: [finding.id], kind: "code" });
		assert.equal(draft.numbers.length, 500, "off-default-branch alerts stay excluded after boundary projection");
		assert.equal(calls, 3, "sync and campaign scoping share projected NDJSON parsing");
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

test("generic alert 404s fail the sync rather than exporting inaccessible sources as verified zero", { skip }, async () => {
	for (const warm of [false, true]) {
		await withExtension({ gh: githubMock() }, async (h) => {
			await synced(h);
			if (!warm) {
				// A new import with no cached payload exercises a first incomplete sync.
				await rm(join(h.home, ARTIFACTS, "radar-cache-acme%2Fwidgets.json"));
			}
			const live = githubMock();
			h.gh = async (command, args, options) => {
				if (args.some((arg) => arg.includes("/secret-scanning/alerts"))) throw new Error("gh: Not Found (HTTP 404)");
				return live(command, args, options);
			};
			if (!warm) await import(`../extension.mjs?unavailable-${++importSeq}`);
			const canvas = warm ? h.canvases[0] : globalThis.canvasTestConfig.canvases[0];
			const invoke = (name, input = {}) => canvas.actions.find((action) => action.name === name).handler({ canvasId: canvas.id, input });
			if (warm) await invoke("refresh");
			await h.waitFor(async () => {
				const state = await invoke("get_state");
				return !state.refreshing && state.refreshError;
			});
			const state = await invoke("get_state");
			assert.notEqual(state.source, "github");
			assert.match(state.refreshError, /alerts are not available/);
			if (warm) {
				assert.equal(state.source, "cache");
				assert.equal(state.totals.secretScanning, 1, "retain the last known secret count");
			} else {
				assert.equal(state.source, "none");
				assert.deepEqual(state.findings, []);
			}
			await assert.rejects(invoke("prepare_campaign", { ids: [campaignId(0)], kind: "code" }), /live GitHub|Cached alerts/);
		});
	}
});

test("overlapping containment mutations serialize unique atomic snapshots in request order", { skip }, async () => {
	await withExtension({ gh: githubMock() }, async (h) => {
		await synced(h);
		const firstGate = Promise.withResolvers();
		const paths = [];
		let entered = false;
		h.beforeRename = async (from, to) => {
			if (!to.endsWith("state-acme%2Fwidgets.json")) return;
			paths.push(from);
			if (paths.length === 1) { entered = true; await firstGate.promise; }
		};
		const first = h.invoke("attack-surface-radar", "contain_finding", { id: campaignId(0) });
		await h.waitFor(() => entered);
		const second = h.invoke("attack-surface-radar", "contain_finding", { id: campaignId(1) });
		const reset = h.invoke("attack-surface-radar", "reset_contains", {});
		const last = h.invoke("attack-surface-radar", "contain_finding", { id: campaignId(2) });
		try {
			assert.equal(paths.length, 1, "only one containment rename may enter at a time");
		} finally {
			firstGate.resolve();
			await Promise.all([first, second, reset, last]);
		}
		assert.equal(paths.length, 4);
		assert.equal(new Set(paths).size, 4);
		assert.deepEqual((await readdir(join(h.home, ARTIFACTS))).filter((name) => name.endsWith(".tmp")), []);
		const saved = JSON.parse(await readFile(join(h.home, ARTIFACTS, "state-acme%2Fwidgets.json"), "utf8"));
		assert.deepEqual(saved.contained, [campaignId(2)]);
		assert.deepEqual((await h.invoke("attack-surface-radar", "get_state", {})).findings.filter((finding) => finding.contained).map((finding) => finding.id), saved.contained);
	});
});

test("campaign context accepts a managed user and passes it through preparation and review", { skip }, async () => {
	await withExtension({ gh: githubMock({ handlers: async (args) => {
		if (args.includes("user")) return { stdout: JSON.stringify({ login: "mona-cat_octo" }) };
	} }) }, async (h) => {
		await synced(h);
		const draft = await h.invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" });
		assert.equal(draft.manager, "mona-cat_octo");
		const reviewed = await h.invoke("attack-surface-radar", "review_campaign", {
			id: draft.id, name: "Managed users", description: "Fix selected alerts", dueDate: "2099-01-01", manager: draft.manager,
		});
		assert.equal(reviewed.manager, "mona-cat_octo");
	});
});

test("unknown fix recovery requires exact confirmation, persists release and never launches automatically", { skip }, async () => {
	const id = campaignId(0);
	await withExtension({ gh: githubMock(), seed: async (dir) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "local-fixes-test-parent.json"), JSON.stringify({
			[id]: { id, requestId: "old", repo: "acme/widgets", canvasId: "attack-surface-radar", status: "unknown" },
		}));
	} }, async (h) => {
		await synced(h);
		for (const input of [{ id, requestId: "old" }, { id, requestId: "wrong", confirm: true }]) {
			await assert.rejects(h.invoke("attack-surface-radar", "acknowledge_fix_session_absent", input), /Explicitly confirm/);
		}
		assert.equal((await h.invoke("attack-surface-radar", "get_state", {})).localFixes[id].status, "unknown");
		await h.invoke("attack-surface-radar", "acknowledge_fix_session_absent", { id, requestId: "old", confirm: true });
		assert.deepEqual(JSON.parse(await readFile(join(h.home, ARTIFACTS, "local-fixes-test-parent.json"), "utf8")), {});
		assert.deepEqual((await h.invoke("attack-surface-radar", "get_state", {})).localFixes, {});
		assert.equal(h.sent.length, 0);
		const next = await h.invoke("attack-surface-radar", "request_copilot", { id });
		assert.notEqual(next.requestId, "old");
		assert.equal(h.sent.length, 1);
		await h.invoke("attack-surface-radar", "record_fix_session", { id, requestId: next.requestId, sessionId: "new-child", appUrl: "ghapp://sessions/new-child" });
	});
});

test("absence confirmation cannot release an unconfirmed fix from another repository", { skip }, async () => {
	const id = campaignId(0);
	await withExtension({ gh: githubMock(), seed: async (dir) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "local-fixes-test-parent.json"), JSON.stringify({
			[id]: { id, requestId: "old", repo: "other/project", canvasId: "attack-surface-radar", status: "unknown" },
		}));
	} }, async (h) => {
		await synced(h);
		await assert.rejects(h.invoke("compliance-scoreboard", "acknowledge_fix_session_absent", { id, requestId: "old", confirm: true }), /this repository/);
		const saved = JSON.parse(await readFile(join(h.home, ARTIFACTS, "local-fixes-test-parent.json"), "utf8"));
		assert.equal(saved[id].repo, "other/project");
		assert.equal(h.sent.length, 0);
	});
});

test("uses the cached sync only for the same repository and says when it is stale", { skip }, async () => {
	const cacheFor = (repo) => async (dir) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, `radar-cache-${encodeURIComponent(repo)}.json`), JSON.stringify({
			repo, syncedAt: "2024-01-02 03:04",
			code: [codeAlert(1, "js/sql-injection", "src/app.js", 7, "error")], dependabot: [], secrets: [],
		}));
	};
	const offline = async (command, args) => {
		if (args[0] === "repo") return { stdout: JSON.stringify({ nameWithOwner: "acme/widgets", url: "https://github.com/acme/widgets" }) };
		throw new Error("network down");
	};
	await withExtension({ gh: offline, seed: cacheFor("acme/widgets") }, async (h) => {
		const state = await settled(h, (current) => current.refreshError);
		assert.equal(state.source, "cache");
		assert.deepEqual(state.findings.map((f) => f.id), [findingId("cs", "js/sql-injection")]);
		assert.match(state.refreshError, /Could not reach GitHub \(network down\)\. Showing the last sync from 2024-01-02 03:04\./);
		await assert.rejects(h.invoke("attack-surface-radar", "prepare_campaign", { ids: [findingId("cs", "js/sql-injection")], kind: "code" }), /Cached alerts cannot be published/);
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
		assert.equal(selectedDependency.id, findingId("dep", "npm/lodash"));
		const postureOpen = h.opens.find((o) => o.canvas.id === "compliance-scoreboard");
		const opened = await postureOpen.canvas.open({ instanceId: postureOpen.instanceId });
		const response = await fetch(`${opened.url}api/action`, {
			method: "POST", headers: { "Content-Type": "application/json", Origin: new URL(opened.url).origin },
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
			if (args[0] === "repo") return { stdout: JSON.stringify({ nameWithOwner: "acme/widgets", url: "https://github.com/acme/widgets" }) };
			requests.push(args);
			if (args.includes("PATCH")) {
				await patchGate;
				assert.ok(args.includes("repos/acme/widgets/code-scanning/alerts/42"));
				assert.ok(args.includes("assignees[]=human-owner"));
				assert.ok(args.includes("assignees[]=github-agentic-autofix[bot]"));
				alert.assignees.push({ login: "github-agentic-autofix[bot]" });
				return { stdout: JSON.stringify(alert) };
			}
			assert.ok(!args.includes("--slurp"));
			assert.equal(args[args.indexOf("--jq") + 1], ALERT_PROJECTIONS["code-scanning"]);
			assert.ok(args.includes("repos/acme/widgets/code-scanning/alerts?state=open&per_page=100"));
			return { stdout: alertLines([alert]) };
		};
		const assigning = invoke("compliance-scoreboard", "assign_copilot", { id: round.id, controlId: theme.id });
		const pending = await h.waitFor(async () => {
			const state = await invoke("compliance-scoreboard", "get_state", {});
			return state.pending ? state : null;
		});
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
			if (args[0] === "repo") return { stdout: JSON.stringify({ nameWithOwner: "acme/widgets", url: "https://github.com/acme/widgets" }) };
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
			assert.deepEqual(JSON.parse(await readFile(join(home, ARTIFACTS, "state-acme%2Fwidgets.json"), "utf8")), { repo: "acme/widgets", contained: [] });
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
				method: "POST", headers: { "Content-Type": "application/json", Origin: new URL(opened.url).origin },
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
		const createResponse = await fetch(`${radarOpen.url}api/action`, { method: "POST", headers: { "Content-Type": "application/json", Origin: new URL(radarOpen.url).origin },
			body: JSON.stringify({ name: "create_campaign", input: directInput }) });
		assert.equal(createResponse.status, 200);
		assert.equal((await createResponse.json()).status, "published");
		assert.deepEqual(publications.at(-1).managers, ["mona"]);
		assert.equal(publications.length, 2);
		await assert.rejects(invoke("attack-surface-radar", "create_campaign", directInput), /confirm creation/);
		assert.equal((await invoke("compliance-scoreboard", "get_state", {})).score, scoreBeforePublish);
		await invoke("attack-surface-radar", "prepare_campaign", { ids: [campaignId(0)], kind: "code" });
		const discardResponse = await fetch(`${radarOpen.url}api/action`, { method: "POST", headers: { "Content-Type": "application/json", Origin: new URL(radarOpen.url).origin },
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
