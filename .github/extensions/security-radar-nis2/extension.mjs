import { execFile } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { promisify } from "node:util";
import { CanvasError, createCanvas, joinSession } from "@github/copilot-sdk/extension";
import {
	DISCLAIMER,
	EMPTY_TOTALS,
	COMPLIANCE_ASK_LABEL,
	EVIDENCE,
	auditBrief,
	buildLiveFindings,
	complianceModel,
	complianceOfflineAnswer,
	compliancePrompt,
	findBannedPhrase,
	findingBrief,
	layoutFindings,
	radarAttachment,
	radarKpis,
	radarOfflineAnswer,
	radarPrompt,
	wantsChange,
	assignCopilotRequest,
	COPILOT_ASSIGNEE_FALLBACK,
	radarFindingUrl,
	canAssignCopilot,
	isCopilotLogin,
	pickRadarAlert,
	radarTotals,
	repoEvidence,
	stripAlerts,
	parseRemoteRepo,
	REPO_PATTERN,
} from "./lib/logic.mjs";
import { renderPage } from "./lib/pages.mjs";
import { createLocalFixLauncher } from "./lib/local-fixes.mjs";
import { createCampaignService, scheduleCampaignProgress } from "./lib/campaigns.mjs";

const execFileAsync = promisify(execFile);

const world = {
	contained: new Set(),
	localFixes: {},
	resetting: false,
	resetEpoch: 0,
	repo: null,
	repoError: null,
	totals: { ...EMPTY_TOTALS },
	radarFindings: [],
	source: "none",
	refreshError: null,
	copilotStatus: null,
	brief: { open: false, at: null, path: null },
	preview: false,
	settings: null,
	settingsSource: null,
	radar: { threads: {}, pending: null, assigned: {} },
	compliance: { threads: {}, pending: null },
	refreshing: false,
	autoRefreshed: false,
	layoutSeed: newSeed(),
};

const servers = new Map();
const streams = new Map();
let campaignService;
let stopCampaignProgress;
let activeAsk = null;
let containmentRepo = null;
let githubOperation = null;
let radarLayout = { findings: null, seed: null, value: [] };
const REPOSITORY_ACTIONS = new Set([
	"request_copilot", "fix_locally", "assign_copilot", "ask_copilot", "explain_finding", "assess_priority",
	"suggest_fix", "prepare_campaign", "create_campaign", "publish_campaign", "draft_dependency_plan", "generate_brief",
]);

function newSeed() {
	return 1 + Math.floor(Math.random() * 1e9);
}

function artifactDir() {
	const home = process.env.COPILOT_HOME || join(homedir(), ".copilot");
	return join(home, "extensions", "security-radar-nis2", "artifacts");
}

function containmentPath(repo) {
	return join(artifactDir(), `state-${encodeURIComponent(repo.toLowerCase())}.json`);
}

function cachePath(repo) {
	return join(artifactDir(), `radar-cache-${encodeURIComponent(repo.toLowerCase())}.json`);
}

async function privateWrite(path, content) {
	try {
		await chmod(path, 0o600);
	} catch (error) {
		if (error.code !== "ENOENT") throw error;
	}
	await writeFile(path, content, { mode: 0o600 });
}

async function loadState(repo) {
	if (containmentRepo === repo.toLowerCase()) return;
	world.contained.clear();
	containmentRepo = repo.toLowerCase();
	try {
		const raw = JSON.parse(await readFile(containmentPath(repo), "utf8"));
		if (raw.repo?.toLowerCase() !== containmentRepo) throw new Error("Saved containment belongs to another repository.");
		world.contained = new Set(Array.isArray(raw.contained) ? raw.contained : []);
	} catch (error) {
		if (error.code !== "ENOENT") session.log(`Could not restore containment: ${error.message}`, { level: "error" });
	}
}

// The cache is keyed by repository: alerts synced from another checkout must not show up here.
async function loadCache(repo) {
	try {
		await chmod(cachePath(repo), 0o600);
		const cache = JSON.parse(await readFile(cachePath(repo), "utf8"));
		if (cache && cache.repo?.toLowerCase() === repo && Array.isArray(cache.code) && Array.isArray(cache.dependabot) && Array.isArray(cache.secrets)) {
			world.radarFindings = buildLiveFindings(cache);
			world.totals = radarTotals(cache, cache.syncedAt);
			world.source = "cache";
			if (cache.settings && typeof cache.settings === "object") {
				world.settings = cache.settings;
				world.settingsSource = "cached";
			}
		}
	} catch (error) {
		if (error.code !== "ENOENT") session.log(`Could not restore radar cache: ${error.message}`, { level: "warning" });
	}
}

async function saveState(contained = containedIds()) {
	const repo = world.repo;
	if (!repo) {
		if (!contained.length) return;
		throw new CanvasError("unknown_repository", "Resolve the current repository before annotating findings.");
	}
	const dir = artifactDir();
	await mkdir(dir, { recursive: true });
	const path = containmentPath(repo);
	await writeFile(
		`${path}.tmp`,
		JSON.stringify({ repo, contained }, null, 2),
		{ mode: 0o600 },
	);
	await rename(`${path}.tmp`, path);
}

function containedIds() {
	return [...world.contained];
}

// Files are checked in the checkout. Settings come from GitHub, live or cached; without a sync they stay unknown.
function currentEvidence() {
	let root = process.cwd();
	try {
		root = repoRoot();
	} catch {
		// joinSession is still resolving; cwd is the checkout.
	}
	const evidence = repoEvidence((path) => existsSync(join(root, path)), world.settings);
	const evidenceSource = {};
	for (const item of EVIDENCE) {
		if (item.paths) evidenceSource[item.id] = evidence[item.id] != null ? "checkout" : "unknown";
		else evidenceSource[item.id] = evidence[item.id] != null ? world.settingsSource ?? "cached" : "unknown";
	}
	return { evidence, evidenceSource };
}

function complianceNow() {
	// Local annotations never close GitHub alerts or improve today's posture.
	return complianceModel([], world.radarFindings, { totals: world.totals, repo: world.repo, ...currentEvidence() });
}

function resetBlocked() {
	return Boolean(githubOperation || world.resetting || world.refreshing || campaignService?.busy || world.radar.pending || world.compliance.pending ||
		Object.values(world.localFixes).some((record) => record.status === "launching"));
}

async function resetAll() {
	if (resetBlocked()) throw new CanvasError("busy", "Wait for the current answer, assignment, refresh, campaign operation or session launch to finish before resetting.");
	world.resetting = true;
	broadcast("*");
	const previousContained = containedIds();
	try {
		await saveState([]);
		try {
			await campaignService.reset(() => localFixLauncher.reset(), { forgetCampaigns: true });
		} catch (error) {
			await saveState(previousContained);
			throw error;
		}
		world.contained.clear();
		world.radar.threads = {};
		world.compliance.threads = {};
		world.preview = false;
		world.brief = { open: false, at: null, path: null };
		world.copilotStatus = null;
		world.resetEpoch++;
		return { reset: true, scope: "all-security-canvases", sessionsPreserved: true, githubAssignmentsPreserved: true };
	} catch (error) {
		session.log(`reset failed: ${error.message}`, { level: "error" });
		throw new CanvasError("reset_failed", `Could not reset the canvases: ${error.message}`);
	} finally {
		world.resetting = false;
		broadcast("*");
	}
}

function stateFor(canvasId) {
	const localFixes = Object.fromEntries(Object.entries(world.localFixes).filter(([, record]) => record.repo === world.repo));
	const campaigns = campaignService?.state();
	const campaignView = campaigns ? { ...campaigns, draft: campaigns.draft?.repo === world.repo ? campaigns.draft : null } : undefined;
	const viewState = {
		resetBlocked: resetBlocked(),
		resetting: world.resetting,
		resetEpoch: world.resetEpoch,
		repo: world.repo,
		repoError: world.repoError,
	};
	if (canvasId === "attack-surface-radar") {
		if (radarLayout.findings !== world.radarFindings || radarLayout.seed !== world.layoutSeed) {
			radarLayout = {
				findings: world.radarFindings, seed: world.layoutSeed,
				value: layoutFindings(world.radarFindings, world.layoutSeed),
			};
		}
		const findings = radarLayout.value.map((finding) => ({
			...finding,
			what: findingBrief(finding).what,
			url: radarFindingUrl(finding, world.repo),
			contained: world.contained.has(finding.id),
		}));
		return {
			...viewState,
			findings,
			kpis: radarKpis(findings, world.totals),
			threads: world.radar.threads,
			pending: world.radar.pending,
			assigned: world.radar.assigned,
			localFixes,
			campaigns: campaignView,
			totals: world.totals,
			source: world.source,
			layoutSeed: world.layoutSeed,
			refreshing: world.refreshing,
			refreshError: world.refreshError,
			copilotStatus: world.copilotStatus,
			disclaimer: DISCLAIMER,
		};
	}
	return {
		...viewState,
		...complianceNow(),
		source: world.source,
		refreshing: world.refreshing,
		refreshError: world.refreshError,
		preview: world.preview,
		brief: world.brief,
		threads: world.compliance.threads,
		pending: world.compliance.pending,
		assigned: world.radar.assigned,
		labels: COMPLIANCE_ASK_LABEL,
		localFixes,
		campaigns: campaignView,
		campaignThemes: Object.fromEntries(complianceNow().controls.map((control) => [control.id,
			world.radarFindings.filter((finding) => finding.controlIds?.includes(control.id)).map((finding) => ({
				...finding, url: radarFindingUrl(finding, world.repo),
				where: finding.path + (finding.line ? `:${finding.line}` : ""),
			}))])),
	};
}

function broadcast(canvasId) {
	for (const [instanceId, entry] of servers) {
		if (canvasId !== "*" && entry.canvasId !== canvasId) continue;
		const body = `data: ${JSON.stringify(stateFor(entry.canvasId))}\n\n`;
		for (const res of streams.get(instanceId) ?? []) res.write(body);
	}
}

function json(res, status, body) {
	const raw = JSON.stringify(body);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(raw),
		"Cache-Control": "no-store",
	});
	res.end(raw);
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		req.on("data", (chunk) => chunks.push(chunk));
		req.on("end", () => {
			const raw = Buffer.concat(chunks).toString("utf8");
			if (!raw) return resolve({});
			try {
				resolve(JSON.parse(raw));
			} catch (error) {
				reject(error);
			}
		});
		req.on("error", reject);
	});
}

async function handleAction(canvasId, name, input = {}) {
	if (!REPOSITORY_ACTIONS.has(name)) return handleActionUnlocked(canvasId, name, input);
	if (githubOperation || world.resetting || (name === "assign_copilot" && (world.radar.pending || world.compliance.pending))) {
		throw new CanvasError("busy", "Wait for the current GitHub operation to finish or the previous question in either canvas.");
	}
	githubOperation = name;
	try {
		return await handleActionUnlocked(canvasId, name, input);
	} finally {
		githubOperation = null;
		broadcast("*");
	}
}

async function handleActionUnlocked(canvasId, name, input = {}) {
	const id = typeof input.id === "string" ? input.id : undefined;
	if (REPOSITORY_ACTIONS.has(name)) {
		if (world.refreshing) throw new CanvasError("busy", "Wait for the GitHub refresh to finish.");
		const previousRepo = world.repo;
		const repo = await resolveRepo();
		if (previousRepo !== repo) throw new CanvasError("repository_changed", "Repository changed. Refresh and select the finding again.");
	}
	if (name === "reset_demo") return resetAll();
	if (world.resetting && name !== "get_state") throw new CanvasError("busy", "The reset is still in progress.");
	if (["prepare_campaign", "create_campaign", "review_campaign", "edit_campaign", "publish_campaign", "refresh_campaigns", "acknowledge_campaign_absent", "discard_campaign"].includes(name)) {
		if (world.refreshing) throw new CanvasError("busy", "Wait for the GitHub refresh to finish.");
		try {
			if (name === "refresh_campaigns") return await campaignService.refresh();
			if (name === "acknowledge_campaign_absent") return await campaignService.acknowledgeAbsent(input);
			if (name === "discard_campaign") {
				await campaignService.reset();
				return { discarded: true };
			}
			if (name === "review_campaign") return await campaignService.review(input);
			if (name === "edit_campaign") return await campaignService.edit(input);
			if (name === "publish_campaign") return await campaignService.publish(input);
			if (name === "create_campaign") {
				if (world.source !== "github") throw new Error("Refresh live GitHub alerts before creating a real campaign.");
				if (canvasId === "compliance-scoreboard") {
					validateThemeSelection(input.controlId, input.ids);
					const control = complianceNow().controls.find((item) => item.id === input.controlId);
					if (campaignService.state().draft?.scopeLabel !== control.title) throw new Error("Prepare the selected theme's scope before creating its campaign.");
				}
				return await campaignService.create(input);
			}
			if (world.source !== "github") throw new Error("Refresh live GitHub alerts before preparing a real campaign. Cached alerts cannot be published.");
			let groups;
			let label;
			if (canvasId === "compliance-scoreboard") {
				const control = complianceNow().controls.find((item) => item.id === input.controlId);
				if (!control) throw new Error("Choose a control theme for this campaign.");
				groups = world.radarFindings.filter((finding) => finding.controlIds?.includes(control.id));
				if (input.ids !== undefined) groups = validateThemeSelection(control.id, input.ids);
				label = control.title;
			} else {
				if (!Array.isArray(input.ids) || !input.ids.length || input.ids.length > 1000 ||
					input.ids.some((value) => typeof value !== "string") || new Set(input.ids).size !== input.ids.length) {
					throw new Error("Select one or more distinct finding groups.");
				}
				groups = input.ids.map((findingId) => {
					const finding = radarFinding(findingId);
					if (!finding) throw new Error("A selected group is no longer on the radar. Select it again.");
					return finding;
				});
				label = "Attack surface remediation";
			}
			return await campaignService.prepare(groups, input.kind, label);
		} catch (error) {
			throw new CanvasError("campaign_error", error.message);
		}
	}
	if (name === "record_fix_session") {
		try {
			return await localFixLauncher.recordSession(canvasId, input);
		} catch (error) {
			throw new CanvasError("invalid_fix_session", error.message);
		}
	}
	if (canvasId === "attack-surface-radar") {
		if (name === "get_state") return stateFor(canvasId);
		if (name === "refresh") {
			if (world.refreshing) throw new CanvasError("busy", "A GitHub refresh is already running.");
			await runRefresh();
			return {
				source: world.source,
				totals: world.totals,
				blips: world.radarFindings.length,
				refreshError: world.refreshError,
			};
		}
		if (name === "contain_finding") {
			const finding = radarFinding(id);
			if (!finding) throw new CanvasError("unknown_finding", "That blip is not on the radar.");
			world.contained.add(finding.id);
			await saveState();
			broadcast("*");
			return { contained: finding.id };
		}
		if (name === "reset_contains") {
			world.contained.clear();
			world.preview = false;
			await saveState();
			broadcast("*");
			return { contained: [] };
		}
		if (name === "request_copilot") {
			if (input.id !== undefined && !radarFinding(id)) throw new CanvasError("unknown_finding", "That blip is no longer on the radar. Select it again.");
			const finding = input.id === undefined ? world.radarFindings.find((item) => item.source !== "secret-scanning" && !world.contained.has(item.id)) : radarFinding(id);
			if (!finding) throw new CanvasError("nothing_to_send", "No uncontained non-secret finding is available for a local fix.");
			if (finding.source === "secret-scanning") throw new CanvasError("not_code", "Secret rotation requires human action; no secret values are loaded.");
			return launchLocalFix(canvasId, finding, radarPrompt("change", finding, "Apply the proposed remediation locally.", { repo: world.repo }));
		}
		if (name === "assign_copilot") {
			const finding = radarFinding(id);
			if (!finding) throw new CanvasError("unknown_finding", "That blip is not on the radar.");
			if (!canAssignCopilot(finding)) throw new CanvasError("not_assignable", "Only code scanning alerts can be assigned to Copilot Autofix.");
			return assignToCopilot(finding, world.radar, canvasId);
		}
		if (name === "explain_finding" || name === "assess_priority" || name === "suggest_fix" || name === "ask_copilot") {
			const finding = radarFinding(id);
			if (!finding) throw new CanvasError("unknown_finding", "That blip is not on the radar.");
			const kind = name === "explain_finding" ? "explain" : name === "assess_priority" ? "assess" : name === "suggest_fix" ? "fix" : "ask";
			const question = typeof input.question === "string" ? input.question.trim() : "";
			if (kind === "ask" && !question) throw new CanvasError("empty_question", "Type a question first.");
			return askRadar(kind, finding, question);
		}
		if (name === "clear_thread") {
			const finding = radarFinding(id) ?? (world.radar.threads[id] ? { id } : null);
			if (!finding) throw new CanvasError("unknown_finding", "That blip is not on the radar.");
			if (world.radar.pending?.key === finding.id) {
				throw new CanvasError("busy", "Wait for Copilot to finish this answer.");
			}
			delete world.radar.threads[finding.id];
			broadcast(canvasId);
			return { cleared: finding.id };
		}
	}
	if (canvasId === "compliance-scoreboard") {
		if (name === "get_state") return stateFor(canvasId);
		if (name === "toggle_preview" || name === "preview_lift" || name === "clear_lift") {
			world.preview = name === "toggle_preview" ? !world.preview : name === "preview_lift";
			broadcast(canvasId);
			return { preview: world.preview };
		}
		if (name === "refresh") {
			if (!world.refreshing) await runRefresh();
			return { source: world.source, asOf: world.totals.asOf };
		}
		if (name === "generate_brief") {
			const dir = artifactDir();
			await mkdir(dir, { recursive: true });
			const path = join(dir, `audit-brief-${encodeURIComponent(world.repo ?? "unresolved")}-${randomUUID()}.md`);
			const model = complianceNow();
			await privateWrite(path, auditBrief(model));
			// Freeze what the brief says, so the cards match the saved file even after a refresh.
			const { score, projected, controls, totals } = model;
			world.brief = { open: true, at: stamp(), path, model: { score, projected, controls, totals, source: world.source } };
			broadcast(canvasId);
			return { path };
		}
		if (name === "close_brief") {
			world.brief = { ...world.brief, open: false };
			broadcast(canvasId);
			return { open: false };
		}
		if (name === "fix_locally") {
			if (input.controlId) {
				const { control, finding } = complianceFinding(input.controlId, id);
				if (finding.source === "secret-scanning") throw new CanvasError("not_code", "Secret rotation requires human action; no secret values are loaded.");
				return launchControlFix(control, "", finding.id);
			}
			const control = complianceNow().controls.find((item) => item.id === id);
			if (!control) throw new CanvasError("unknown_control", "Pick one of the five control themes.");
			return launchControlFix(control);
		}
		if (name === "assign_copilot") {
			const { control, finding } = complianceFinding(input.controlId, id);
			if (!canAssignCopilot(finding)) throw new CanvasError("not_assignable", "Only code scanning alerts can be assigned to Copilot Autofix.");
			return assignToCopilot(finding, world.compliance, canvasId, control.id);
		}
		if (name === "assess_priority") {
			const { control, finding } = complianceFinding(input.controlId, id);
			const attachment = finding.source === "secret-scanning" ? null : radarAttachment(finding, repoRoot());
			return askInPanel({
				canvasId, store: world.compliance, key: control.id, kind: "assess",
				question: `Assess priority · ${finding.title}`,
				prompt: radarPrompt("assess", finding, "", { attached: Boolean(attachment), repo: world.repo }) +
					`\nThis analysis is displayed in the NIS2 / DORA ${control.title} theme. It is advisory triage, not a compliance assessment; do not change posture scores.`,
				label: `NIS2 / DORA · Assess priority: ${finding.title}`,
				attachment, startNote: "Copilot is assessing context and evidence…", answerTimeoutMs: 90_000,
				fallback: () => radarOfflineAnswer("assess", finding),
			});
		}
		if (name === "draft_dependency_plan") {
			let selected;
			try {
				selected = validateThemeSelection(input.controlId, input.ids);
			} catch (error) {
				throw new CanvasError("invalid_selection", error.message);
			}
			if (selected.some((finding) => finding.source !== "dependabot")) {
				throw new CanvasError("invalid_selection", "Select only open dependency groups mapped to this theme.");
			}
			const control = complianceNow().controls.find((item) => item.id === input.controlId);
			return askCompliance("dependencies", {
				...control,
				alerts: selected.reduce((sum, finding) => sum + finding.count, 0),
				findings: selected.map((finding) => ({
					...finding, where: finding.path, url: radarFindingUrl(finding, world.repo),
				})),
				more: 0,
			});
		}
		const kinds = { draft_plan: "plan", draft_board: "board", ask_auditor: "auditor", ask_copilot: "ask", draft_evidence: "evidence" };
		if (kinds[name]) {
			const control = complianceNow().controls.find((item) => item.id === id);
			if (!control) throw new CanvasError("unknown_control", "Pick one of the five control themes.");
			if (kinds[name] === "evidence" && control.id !== "incident") {
				throw new CanvasError("unknown_control", "Use the incident response evidence theme for this checklist.");
			}
			const question = typeof input.question === "string" ? input.question.trim() : "";
			if (kinds[name] === "ask" && !question) throw new CanvasError("empty_question", "Type a question first.");
			return askCompliance(kinds[name], control, question);
		}
		if (name === "clear_thread") {
			if (world.compliance.pending?.key === id) throw new CanvasError("busy", "Wait for Copilot to finish this answer.");
			delete world.compliance.threads[id];
			broadcast(canvasId);
			return { cleared: id };
		}
	}
	throw new CanvasError("unknown_action", `Unknown action ${name}`);
}

const ASK_LABEL = { explain: "Explain the vuln", assess: "Assess priority", fix: "Suggest a fix" };
// The chat may still be busy with an earlier turn, so waiting for our prompt and waiting for
// the answer are timed separately.
const ASK_QUEUE_TIMEOUT_MS = 45_000;
const ASK_ANSWER_TIMEOUT_MS = 30_000;
let askSeq = 0;

function repoRoot() {
	// workspacePath can be the session state directory; only trust it when it is a git checkout.
	return session.workspacePath && existsSync(join(session.workspacePath, ".git")) ? session.workspacePath : process.cwd();
}

function shortPath(value) {
	if (typeof value !== "string" || !value) return null;
	if (!isAbsolute(value)) return value;
	const rel = relative(process.cwd(), value);
	if (rel && !rel.startsWith("..")) return rel;
	return value.split("/").slice(-3).join("/");
}

function toolNote(data) {
	const name = String(data?.toolName ?? "");
	const args = data?.arguments && typeof data.arguments === "object" ? data.arguments : {};
	const path = shortPath(args.path ?? args.file ?? args.filePath);
	if (name === "create_pull_request") return "Opening the pull request…";
	if (path && /edit|create|write|patch/i.test(name)) return `Editing ${path}…`;
	if (path && /view|read|file/i.test(name)) return `Reading ${path}…`;
	if (/grep|glob|search/i.test(name)) return "Searching the repository…";
	if (path) return `Inspecting ${path}…`;
	if (/bash|shell|powershell/i.test(name)) {
		const cmd = String(args.command ?? "");
		if (/git\s+(checkout\s+-b|switch\s+-c|branch\s)/.test(cmd)) return "Creating the branch…";
		if (/git\s+commit/.test(cmd)) return "Committing…";
		if (/git\s+push/.test(cmd)) return "Pushing the branch…";
		if (/\b(test|vitest|jest|build|tsc|lint)\b/.test(cmd)) return "Running build and tests…";
		return "Running a quick check…";
	}
	return null;
}

function askRadar(kind, finding, question) {
	// A free-form request to change code gets the editing prompt; secrets are never "fixed" from the panel.
	if (kind === "ask" && finding.source !== "secret-scanning" && wantsChange(question)) kind = "change";
	if (kind === "change") return launchLocalFix("attack-surface-radar", finding, radarPrompt(kind, finding, question, { repo: world.repo }));
	const attachment = kind === "assess" && finding.source === "secret-scanning" ? null : radarAttachment(finding, repoRoot());
	const typed = kind === "ask";
	return askInPanel({
		canvasId: "attack-surface-radar",
		store: world.radar,
		key: finding.id,
		question: typed ? question.slice(0, 500) : ASK_LABEL[kind],
		kind,
		prompt: radarPrompt(kind, finding, question, { attached: Boolean(attachment), repo: world.repo }),
		label: typed ? `Radar · ${finding.title}: ${question.slice(0, 500)}` : `Radar · ${ASK_LABEL[kind]}: ${finding.title}`,
		attachment,
		startNote: kind === "assess" ? "Copilot is assessing context and evidence…" : "Copilot is reading the alert…",
		...(kind === "assess" ? { answerTimeoutMs: 90_000 } : {}),
		fallback: () => radarOfflineAnswer(kind, finding),
	});
}

async function launchLocalFix(canvasId, finding, prompt) {
	if (activeAsk) throw new CanvasError("busy", "Wait for the Copilot panel answer before launching a fix in the shared chat.");
	const instanceId = [...servers].find(([, entry]) => entry.canvasId === canvasId)?.[0];
	if (!instanceId) throw new CanvasError("canvas_closed", "Open the canvas before launching a fix.");
	try {
		return await localFixLauncher.launch({
			canvasId, instanceId, id: finding.id, title: finding.title, prompt, requestId: randomUUID(), repo: world.repo,
		});
	} catch (error) {
		session.log(`local fix launch failed: ${error.message}`, { level: "error" });
		throw new CanvasError("launch_failed", `Could not launch the dedicated fix session: ${error.message}`);
	}
}

function complianceFinding(controlId, findingId) {
	const control = complianceNow().controls.find((item) => item.id === controlId);
	if (!control) throw new CanvasError("unknown_control", "Pick one of the five control themes.");
	const finding = radarFinding(findingId);
	if (!finding || !finding.controlIds?.includes(control.id)) {
		throw new CanvasError("unknown_finding", "Pick a finding shown for this control theme.");
	}
	return { control, finding };
}

function validateThemeSelection(controlId, ids) {
	if (!Array.isArray(ids) || !ids.length || ids.length > 1000 ||
		ids.some((id) => typeof id !== "string") || new Set(ids).size !== ids.length) {
		throw new Error("Select one or more distinct finding groups.");
	}
	return ids.map((id) => complianceFinding(controlId, id).finding);
}

function launchControlFix(control, question = "", findingId = null) {
	const finding = world.radarFindings.filter((item) => item.controlIds?.includes(control.id))
		.find((item) => item && item.source !== "secret-scanning" && (!findingId || item.id === findingId));
	if (!finding) throw new CanvasError("nothing_to_fix", "This theme has no mapped code or dependency finding to fix locally.");
	return launchLocalFix("compliance-scoreboard", finding, radarPrompt("change", finding,
		`Fix this finding for the ${control.title} control theme. Do not change cloud settings.${question ? ` User request: ${question}` : ""}`, { repo: world.repo }));
}

function askCompliance(kind, control, question) {
	const model = { ...complianceNow(), source: world.source };
	const text = kind === "ask" ? question.slice(0, 500) : COMPLIANCE_ASK_LABEL[kind];
	return askInPanel({
		canvasId: "compliance-scoreboard",
		store: world.compliance,
		key: control.id,
		question: text,
		kind,
		prompt: compliancePrompt(kind, control, model, question),
		label: `Compliance · ${control.title}: ${text}`,
		attachment: null,
		startNote: "Copilot is weighing the evidence…",
		fallback: () => complianceOfflineAnswer(kind, control),
	});
}

function askInPanel(job) {
	const { canvasId, store, key } = job;
	if (activeAsk || githubOperation === "assign_copilot" || store.pending) throw new CanvasError("busy", "Copilot is still answering the previous question. Wait before asking in either security canvas.");
	activeAsk = job;
	const thread = (store.threads[key] ??= []);
	const entry = {
		id: `ask-${++askSeq}`,
		kind: job.kind,
		question: job.question,
		status: "pending",
		note: "Waiting for Copilot…",
		answer: null,
		offline: false,
		// Shown under "View prompt": exactly what the chat received, minus the internal nonce.
		prompt: job.prompt,
		context: job.attachment ? `Attached: ${job.attachment.displayName} (lines ${job.attachment.lineRange.start}–${job.attachment.lineRange.end})` : null,
	};
	// A per-ask nonce ties the shared chat turn back to this panel.
	job.nonce = `cv-${randomUUID().slice(0, 8)}`;
	job.prompt = `${job.prompt}\n\n(Canvas request ${job.nonce}. Internal reference, do not repeat it.)`;
	thread.push(entry);
	if (thread.length > 12) thread.splice(0, thread.length - 12);
	store.pending = { key, findingId: key, entryId: entry.id };
	broadcast("*");
	runAsk(job, entry).catch((error) => {
		session.log(`${canvasId} ask crashed: ${error instanceof Error ? error.message : "unknown"}`, { level: "warning" });
	});
	return { queued: true, id: key, entry: entry.id };
}

async function runAsk(job, entry) {
	const unsubscribe = [];
	let answer = "";
	try {
		answer = await collectAnswer(job, entry, unsubscribe);
	} catch (error) {
		session.log(`${job.canvasId} ask failed: ${error instanceof Error ? error.message : "unknown"}`, { level: "warning" });
	} finally {
		for (const off of unsubscribe) {
			try {
				off();
			} catch {
				// Unsubscribe must never keep the panel busy.
			}
		}
		if (!answer || findBannedPhrase(answer)) {
			entry.answer = job.fallback();
			entry.offline = true;
		} else {
			entry.answer = answer.slice(0, 2400);
		}
		entry.status = "done";
		entry.note = null;
		job.store.pending = null;
		activeAsk = null;
		try {
			job.onDone?.(entry);
		} catch {
			// Progress bookkeeping must never keep the panel busy.
		}
		broadcast("*");
	}
}

async function collectAnswer(job, entry, unsubscribe) {
	// The ask runs in this shared chat session, so only events after our own prompt count.
	const { prompt, label, attachment, canvasId, nonce } = job;
	const answerTimeoutMs = job.answerTimeoutMs ?? ASK_ANSWER_TIMEOUT_MS;
	let started = false;
	let finished = false;
	let lastMessage = "";
	let summary = "";
	await new Promise((resolve) => {
		let timer = setTimeout(() => done(), ASK_QUEUE_TIMEOUT_MS);
		const rearm = () => {
			clearTimeout(timer);
			timer = setTimeout(() => done(), answerTimeoutMs);
		};
		const done = () => {
			if (finished) return;
			finished = true;
			clearTimeout(timer);
			resolve();
		};
		unsubscribe.push(
			session.on("user.message", (event) => {
				if (finished) return;
				const data = event.data ?? {};
				const text = [data.content, data.transformedContent].filter((v) => typeof v === "string").join("\n");
				const ours = text.includes(nonce) || data.content === label;
				if (!started && ours) {
					started = true;
					rearm();
					entry.note = job.startNote;
					broadcast(canvasId);
					return;
				}
				// Someone typed in the shared chat: the next reply is theirs, not the panel's.
				if (started && !ours) {
					lastMessage = "";
					summary = "";
					done();
				}
			}),
			session.on("tool.execution_start", (event) => {
				if (!started || finished) return;
				// Long edit/test runs stay alive as long as Copilot keeps working.
				if (job.answerTimeoutMs) rearm();
				if (event.data?.toolName === "task_complete") {
					const text = event.data?.arguments?.summary;
					if (typeof text === "string") summary = text.trim();
					return;
				}
				const note = toolNote(event.data);
				if (note && note !== entry.note) {
					entry.note = note;
					broadcast(canvasId);
				}
			}),
			session.on("assistant.message", (event) => {
				if (!started || finished || event.data?.parentToolCallId) return;
				const text = event.data?.content;
				if (typeof text !== "string" || !text.trim()) return;
				lastMessage = text.trim();
				// A reply with no tool calls is the final answer; later chat chatter must not overwrite it.
				if (!event.data?.toolRequests?.length) done();
			}),
			session.on("session.idle", () => {
				if (started) done();
			}),
			session.on("abort", () => {
				if (started) done();
			}),
		);
		session.send({ prompt, displayPrompt: label, ...(attachment ? { attachments: [attachment] } : {}) }).catch((error) => {
			session.log(`${canvasId} ask failed: ${error instanceof Error ? error.message : "unknown"}`, { level: "warning" });
			done();
		});
	});
	return lastMessage || summary;
}

function radarFinding(id) {
	return world.radarFindings.find((finding) => finding.id === id) ?? null;
}

// Same as the alert page's "Assign to Copilot": PATCH the alert's assignees with the Copilot bot.
// The thread lives in the calling canvas; both views share the assignment.
async function assignToCopilot(finding, store, canvasId, threadKey = finding.id) {
	const assigned = world.radar.assigned;
	if (world.radar.pending || world.compliance.pending) throw new CanvasError("busy", "Copilot is still answering the previous question.");
	const thread = (store.threads[threadKey] ??= []);
	const entry = {
		id: `ask-${++askSeq}`,
		kind: "assign",
		question: threadKey === finding.id ? "Assign to Copilot" : `Assign to Copilot · ${finding.title}`,
		status: "pending",
		note: "Finding the alert on GitHub…",
		answer: null,
		offline: false,
		prompt: null,
		context: null,
	};
	thread.push(entry);
	if (thread.length > 12) thread.splice(0, thread.length - 12);
	store.pending = { key: threadKey, findingId: finding.id, entryId: entry.id };
	broadcast("*");
	let url = null;
	try {
		const expectedRepo = world.repo;
		const repo = await resolveRepo();
		if (repo !== expectedRepo || !world.radarFindings.includes(finding)) throw new Error("Repository changed. Refresh and select the finding again.");
		const alerts = await ghPages(`repos/${repo}/code-scanning/alerts?state=open&per_page=100`);
		const alert = pickRadarAlert(alerts, finding);
		if (!alert) throw new Error("No open code scanning alert matches this blip any more.");
		url = alert.html_url;
		if ((alert.assignees ?? []).some((a) => isCopilotLogin(a.login))) {
			assigned[finding.id] = { number: alert.number, url };
			entry.answer = `Alert #${alert.number} is already assigned to Copilot. Copilot Autofix is working on it; follow its draft pull request from the [alert page](${url}).`;
		} else {
			let request = assignCopilotRequest(alert, repo);
			const showRequest = () => {
				entry.prompt = `PATCH /${request.path}\n${JSON.stringify(request.body, null, 2)}`;
				entry.context = `GitHub REST API · Update a code scanning alert · alert #${alert.number}`;
			};
			showRequest();
			entry.note = `Assigning alert #${alert.number} to Copilot…`;
			broadcast(canvasId);
			const patch = async () => {
				const args = ["api", "--hostname", "github.com", "-X", "PATCH", request.path, "-H", "Accept: application/vnd.github+json"];
				for (const login of request.body.assignees) args.push("-f", `assignees[]=${login}`);
				const { stdout } = await execFileAsync("gh", args, { cwd: session.workspacePath, timeout: 15000 });
				return JSON.parse(stdout || "{}");
			};
			let updated;
			try {
				updated = await patch();
			} catch (error) {
				if (!/cannot be assigned/i.test(String(error?.stderr || error?.message))) throw error;
				request = assignCopilotRequest(alert, repo, COPILOT_ASSIGNEE_FALLBACK);
				showRequest();
				broadcast(canvasId);
				updated = await patch();
			}
			const ok = (updated.assignees ?? []).some((a) => isCopilotLogin(a.login));
			if (!ok) throw new Error("GitHub accepted the request but Copilot is not listed as an assignee. Check that agentic Autofix is enabled for this repository.");
			assigned[finding.id] = { number: alert.number, url };
			entry.answer = `Assigned alert #${alert.number} to Copilot. Copilot Autofix now works on it in the cloud and opens a draft pull request linked from the [alert page](${url}). Agentic fixes use AI credits.`;
		}
	} catch (error) {
		const detail = String(error?.stderr || error?.message || "unknown error").trim().split("\n").pop();
		const link = url ? ` Open the [alert page](${url}) to check.` : "";
		entry.answer = /cannot be assigned/i.test(detail)
			? `GitHub refused (HTTP 422) for both Copilot Autofix bots. Agentic Autofix may be off for this repository, or the alert is not eligible.${link}`
			: `Could not assign this alert to Copilot: ${detail.slice(0, 300)}${link}`;
		entry.offline = true;
		session.log(`radar assign_copilot failed: ${detail}`, { level: "warning" });
	} finally {
		entry.status = "done";
		entry.note = null;
		store.pending = null;
		broadcast("*");
	}
	return { id: finding.id, assigned: assigned[finding.id] ?? null };
}

function stamp(date = new Date()) {
	const pad = (n) => String(n).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

async function runRefresh() {
	if (githubOperation) throw new CanvasError("busy", "Wait for the current GitHub operation to finish.");
	githubOperation = "refresh";
	try {
		return await runRefreshUnlocked();
	} finally {
		githubOperation = null;
		broadcast("*");
	}
}

async function runRefreshUnlocked() {
	if (campaignService?.busy) throw new CanvasError("busy", "Wait for the campaign operation to finish.");
	world.refreshing = true;
	world.refreshError = null;
	broadcast("attack-surface-radar");
	try {
		// New bearings only when fresh data landed, so a failed sync never fakes an update.
		if (await refreshFromGitHub()) world.layoutSeed = newSeed();
		if (campaignService?.state().receipts.some((receipt) => receipt.status === "published" || receipt.status === "unknown")) {
			try { await campaignService.refresh(); } catch {
				// Campaign errors are visible independently from successfully refreshed alerts.
			}
		}
	} finally {
		world.refreshing = false;
		broadcast("*");
	}
}

// Swap the whole radar only after the alert APIs answer, so a flaky network never shows half a picture.
async function refreshFromGitHub() {
	let repo;
	try {
		repo = await resolveRepo();
	} catch (error) {
		world.repoError = error.message;
		world.refreshError = error.message;
		return false;
	}
	if (world.source === "none") await loadCache(repo);
	try {
		const [code, dependabot, secrets, settings] = await Promise.all([
			ghPages(`repos/${repo}/code-scanning/alerts?state=open&per_page=100`).catch(featureOff),
			ghPages(`repos/${repo}/dependabot/alerts?state=open&per_page=100`).catch(featureOff),
			ghPages(`repos/${repo}/secret-scanning/alerts?state=open&per_page=100`).catch(featureOff),
			repoSettings(repo),
		]);
		// Alert types that are switched off count as empty; a repository where none is reachable is an error.
		const off = [code, dependabot, secrets].filter((value) => value instanceof FeatureOff);
		if (off.length === 3) throw off[0].error;
		const unwrap = (value) => (value instanceof FeatureOff ? [] : value);
		const raw = {
			...stripAlerts({ code: unwrap(code), dependabot: unwrap(dependabot), secrets: unwrap(secrets) }),
			defaultBranch: settings?.default_branch,
		};
		const findings = buildLiveFindings(raw);
		const syncedAt = stamp();
		world.radarFindings = findings;
		world.radar.assigned = {};
		world.totals = radarTotals(raw, syncedAt);
		world.source = "github";
		world.refreshError = null;
		if (settings) {
			world.settings = settings;
			world.settingsSource = "live";
		} else if (world.settings) world.settingsSource = "cached";
		try {
			const dir = artifactDir();
			await mkdir(dir, { recursive: true });
			const temp = join(dir, `radar-cache-${randomUUID()}.tmp`);
			await writeFile(
				temp,
				JSON.stringify({ repo, syncedAt, ...raw, settings: settings ?? world.settings }),
				{ mode: 0o600 },
			);
			await rename(temp, cachePath(repo));
		} catch (error) {
			session.log(`Could not save radar cache: ${error.message}`, { level: "warning" });
		}
		return true;
	} catch (error) {
		// Data on screen is no longer live, so the pill must stop claiming it is.
		if (world.source === "github") world.source = "cache";
		if (world.settingsSource === "live") world.settingsSource = "cached";
		const reason = syncFailureReason(error);
		world.refreshError = world.source === "cache"
			? `Could not reach GitHub (${reason}). Showing the last sync from ${world.totals.asOf}.`
			: `Could not sync from GitHub: ${reason}`;
		session.log(`radar refresh failed: ${error instanceof Error ? error.message : "unknown"}`, { level: "warning" });
		return false;
	}
}

class FeatureOff {
	constructor(error) {
		this.error = error;
	}
}

// 403/404 answers that mean "this alert type is not enabled here" are not sync failures on their own.
function featureOff(error) {
	const text = String(error?.stderr || error?.message || "");
	if (/\b(403|404)\b/.test(text) && /not enabled|disabled|no analysis found|must be enabled|not found/i.test(text)) return new FeatureOff(error);
	throw error;
}

function syncFailureReason(error) {
	const text = String(error?.stderr || error?.message || "unknown error");
	if (/ENOENT/.test(text)) return "the gh CLI is not installed";
	if (/gh auth login|not logged in|authentication|\b401\b|bad credentials/i.test(text)) return "gh is not authenticated, run `gh auth login`";
	if (/\b(403|404)\b/.test(text)) return "alerts are not available: code scanning or Dependabot may not be enabled, or access is missing";
	return text.trim().split("\n").pop().slice(0, 200);
}

// Single source for the repository: gh first, then the origin remote of the checkout.
async function resolveRepo() {
	const cwd = repoRoot();
	let ghError;
	try {
		const { GH_REPO: _override, ...env } = process.env;
		const { stdout } = await execFileAsync("gh", ["repo", "view", "--json", "nameWithOwner,url"], { cwd, env, timeout: 8000 });
		const { nameWithOwner: repo, url } = JSON.parse(stdout);
		if (typeof repo === "string" && REPO_PATTERN.test(repo) && parseRemoteRepo(url)?.toLowerCase() === repo.toLowerCase()) return remember(repo);
		throw new Error("Only repositories hosted on github.com are supported.");
	} catch (error) {
		ghError = error;
	}
	try {
		const { stdout } = await execFileAsync("git", ["remote", "get-url", "origin"], { cwd, timeout: 5000 });
		const repo = parseRemoteRepo(stdout);
		if (repo) return remember(repo);
	} catch {
		// Fall through to the error below.
	}
	await remember(null);
	const hint = ghError && /gh auth login|not logged in/i.test(String(ghError.stderr || ghError.message)) ? " gh is not authenticated; run `gh auth login`." : "";
	throw new Error(`Could not determine the GitHub repository for this session. Open the session in a git checkout with a github.com origin remote.${hint}`);
}

async function remember(repo) {
	repo = repo?.toLowerCase() ?? null;
	if (world.repo?.toLowerCase() !== repo?.toLowerCase()) {
		world.contained.clear();
		containmentRepo = null;
		world.radarFindings = [];
		world.totals = { ...EMPTY_TOTALS };
		world.settings = null;
		world.settingsSource = null;
		world.source = "none";
		world.refreshError = null;
		world.radar.assigned = {};
		world.radar.threads = {};
		world.compliance.threads = {};
		world.preview = false;
		world.brief = { open: false, at: null, path: null };
		world.copilotStatus = null;
		world.resetEpoch++;
	}
	world.repo = repo;
	world.repoError = null;
	if (repo) await loadState(repo);
	broadcast("*");
	return repo;
}

// Keep security settings and default-branch metadata, never the full repository payload.
async function repoSettings(repo) {
	try {
		const { stdout } = await execFileAsync("gh", ["api", "--hostname", "github.com", `repos/${repo}`, "--jq",
			". as $repo | (.security_and_analysis // {}) + {default_branch: $repo.default_branch}"], {
			cwd: session.workspacePath,
			timeout: 8000,
		});
		const parsed = JSON.parse(stdout || "null");
		return parsed && typeof parsed === "object" ? parsed : null;
	} catch {
		return null;
	}
}

// gh cannot combine --slurp and --jq: projected secret metadata uses one JSON object per line.
function ghPages(path, headers = []) {
	const secrets = /\/secret-scanning\/alerts(?:\?|\/|$)/.test(path);
	const output = secrets
		? ["--jq", ".[] | {number, state, secret_type, secret_type_display_name, html_url}"] : ["--slurp"];
	return execFileAsync("gh", ["api", "--hostname", "github.com", "--paginate", ...output, path, ...headers], {
		cwd: session.workspacePath,
		timeout: 120000,
		maxBuffer: 16 * 1024 * 1024,
	}).then(({ stdout }) => {
		if (secrets) return stdout.trim() ? stdout.trim().split("\n").map((line) => JSON.parse(line)) : [];
		const pages = JSON.parse(stdout || "[]");
		if (!Array.isArray(pages)) throw new Error(`unexpected response for ${path}`);
		return pages.flat();
	});
}

async function campaignContext() {
	const expectedRepo = world.repo;
	const repo = await resolveRepo();
	if (repo !== expectedRepo) throw new Error("Repository changed. Refresh and prepare the campaign again.");
	const metadata = await campaignApi("GET", `repos/${repo}`);
	if (!Number.isSafeInteger(metadata.id) || typeof metadata.default_branch !== "string") throw new Error("Invalid repository metadata from GitHub.");
	const user = await campaignApi("GET", "user");
	if (typeof user.login !== "string" || !/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(user.login)) {
		throw new Error("Could not identify the authenticated gh user for the campaign manager.");
	}
	return { repo, repositoryId: metadata.id, branch: metadata.default_branch, organization: metadata.owner?.type === "Organization", manager: user.login };
}

async function campaignApi(method, path, body) {
	const args = ["api", "--hostname", "github.com", "--method", method, path, "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"];
	let payload;
	try {
		if (body) {
			await mkdir(artifactDir(), { recursive: true });
			payload = join(artifactDir(), `campaign-request-${randomUUID()}.json`);
			await writeFile(payload, JSON.stringify(body), { mode: 0o600 });
			args.push("--input", payload);
		}
		const { stdout } = await execFileAsync("gh", args, { cwd: repoRoot(), timeout: 20000, maxBuffer: 16 * 1024 * 1024 });
		return JSON.parse(stdout);
	} finally {
		if (payload) await rm(payload, { force: true });
	}
}

function startServer(canvasId) {
	const token = randomBytes(32).toString("hex");
	const prefix = `/${token}/`;
	const server = createServer(async (req, res) => {
		try {
			const origin = `http://127.0.0.1:${server.address().port}`;
			res.setHeader("Referrer-Policy", "no-referrer");
			res.setHeader("X-Content-Type-Options", "nosniff");
			res.setHeader("Cache-Control", "no-store");
			if (req.headers.host !== new URL(origin).host || (req.headers.origin && req.headers.origin !== origin)) {
				json(res, 403, { error: "Invalid canvas host or origin." });
				return;
			}
			const url = new URL(req.url ?? "/", origin);
			if (!url.pathname.startsWith(prefix)) {
				json(res, 403, { error: "Canvas capability required." });
				return;
			}
			url.pathname = `/${url.pathname.slice(prefix.length)}`;
			if (req.method === "GET" && url.pathname === "/") {
				const html = renderPage(canvasId, stateFor(canvasId));
				res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
				res.end(html);
				return;
			}
			if (req.method === "GET" && url.pathname === "/api/state") {
				json(res, 200, stateFor(canvasId));
				return;
			}
			if (req.method === "GET" && url.pathname === "/events") {
				res.writeHead(200, {
					"Content-Type": "text/event-stream",
					"Cache-Control": "no-cache",
					Connection: "keep-alive",
				});
				res.write(`data: ${JSON.stringify(stateFor(canvasId))}\n\n`);
				const set = streams.get(server.instanceId) ?? new Set();
				set.add(res);
				streams.set(server.instanceId, set);
				req.on("close", () => set.delete(res));
				return;
			}
			if (req.method === "POST" && url.pathname === "/api/action") {
				if (req.headers.origin !== origin || req.headers["content-type"]?.split(";")[0].trim().toLowerCase() !== "application/json") {
					json(res, 403, { error: "Canvas actions require same-origin JSON." });
					return;
				}
				const body = await readBody(req);
				if (body.repo !== undefined && body.repo !== world.repo) throw new CanvasError("repository_changed", "Repository changed. Refresh and select the finding again.");
				const result = await handleAction(canvasId, String(body.name ?? ""), body.input ?? {});
				json(res, 200, result);
				return;
			}
			json(res, 404, { error: "not_found" });
		} catch (error) {
			const message = error instanceof Error ? error.message : "request failed";
			json(res, 400, { error: message });
		}
	});
	return new Promise((resolve, reject) => {
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			if (!address || typeof address === "string") {
				reject(new Error("loopback server did not bind"));
				return;
			}
			resolve({ server, url: `http://127.0.0.1:${address.port}${prefix}`, canvasId });
		});
	});
}

const inputSchema = {
	type: "object",
	additionalProperties: false,
	properties: {
		note: { type: "string", maxLength: 80 },
	},
};

function defineCanvas(id, displayName, description, actions) {
	return createCanvas({
		id,
		displayName,
		description,
		inputSchema,
		actions: [...actions, ...campaignActions(id), action("reset_demo", "Reset shared answers, containment, preview, known campaign tracking and confirmed local session links across both security canvases. Unconfirmed receipts, existing sessions, real GitHub assignments and campaigns on GitHub are preserved."),
		action("record_fix_session", "Record the actual dedicated worktree session created for a local fix.", {
			requestId: { type: "string", minLength: 1 },
			sessionId: { type: "string", minLength: 1 },
			appUrl: { type: "string", minLength: 1 },
		})],
		open: async (ctx) => {
			let entry = servers.get(ctx.instanceId);
			if (!entry || entry.canvasId !== id) {
				if (entry) {
					servers.delete(ctx.instanceId);
					await stopServer(ctx.instanceId, entry);
				}
				entry = await startServer(id);
				entry.server.instanceId = ctx.instanceId;
				servers.set(ctx.instanceId, entry);
			}
			sessionReady.then(() => {
				if (stopCampaignProgress || !servers.size) return;
				stopCampaignProgress = scheduleCampaignProgress(campaignService, {
					canRefresh: () => !githubOperation && !world.refreshing && !world.resetting,
					onError: (error) => session.log(`Automatic campaign progress refresh failed: ${error.message}`, { level: "error" }),
				});
			});
			if (!world.autoRefreshed && !world.refreshing) {
				world.autoRefreshed = true;
				// Rehydrated opens can land while joinSession is still resolving.
				sessionReady.then(runRefresh).catch(() => {});
			}
			return {
				title: displayName,
				status: "Ready",
				url: entry.url,
			};
		},
		onClose: async (ctx) => {
			const entry = servers.get(ctx.instanceId);
			if (!entry) return;
			servers.delete(ctx.instanceId);
			if (!servers.size) {
				stopCampaignProgress?.();
				stopCampaignProgress = undefined;
			}
			await stopServer(ctx.instanceId, entry);
		},
	});
}

// Open SSE responses keep server.close() waiting forever, so end them first.
async function stopServer(instanceId, entry) {
	for (const res of streams.get(instanceId) ?? []) {
		try {
			res.end();
		} catch {
			// Already gone.
		}
	}
	streams.delete(instanceId);
	entry.server.closeAllConnections?.();
	await new Promise((resolve) => entry.server.close(() => resolve()));
}

function action(name, description, extra = {}) {
	return {
		name,
		description,
		inputSchema: {
			type: "object",
			additionalProperties: false,
			properties: { id: { type: "string" }, ...extra },
		},
		handler: async (ctx) => handleAction(ctx.canvasId, name, ctx.input ?? {}),
	};
}

function campaignActions(canvasId) {
	return [
		action("create_campaign", "Create the code campaign on GitHub after the user confirms the displayed exact scope and form. Uses the authenticated gh user as manager; never retries an unconfirmed submission.", {
			ids: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 1000, uniqueItems: true },
			name: { type: "string", maxLength: 50 }, description: { type: "string", maxLength: 195 },
			dueDate: { type: "string" }, revision: { type: "string" }, confirm: { type: "boolean" },
			controlId: { type: "string" },
		}),
		action("prepare_campaign", "Prepare a local campaign from selected radar groups (ids) or a posture theme (controlId). Requires live alerts. Secrets finalize on GitHub; dependencies are excluded.", {
			ids: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 1000, uniqueItems: true },
			controlId: { type: "string" }, kind: { type: "string", enum: ["code", "secrets"] },
		}),
		action("review_campaign", "Validate and save the exact local code campaign review; does not publish.", {
			name: { type: "string", maxLength: 50 }, description: { type: "string", maxLength: 195 },
			dueDate: { type: "string" }, manager: { type: "string" },
		}),
		action("edit_campaign", "Return the reviewed local campaign to editable preparation without publishing."),
		action("publish_campaign", "Publish the reviewed code campaign only after explicit user confirmation. Triggers GitHub notifications and Autofix.", {
			revision: { type: "string" }, confirm: { type: "boolean" },
		}),
		action("refresh_campaigns", "Refresh actual campaign progress or reconcile an unconfirmed publication without retrying it."),
		action("acknowledge_campaign_absent", "Release an unconfirmed receipt only after the user has explicitly checked GitHub and confirmed that no campaign was created. Never retry automatically.", {
			confirm: { type: "boolean" },
		}),
		action("discard_campaign", "Discard only the local preparation; preserve published campaigns and unconfirmed publication receipts."),
	];
}

let markSessionReady;
const sessionReady = new Promise((resolve) => {
	markSessionReady = resolve;
});
const session = await joinSession({
	canvases: [
		defineCanvas(
			"attack-surface-radar",
			"Attack surface radar",
			"Radar of open code scanning, Dependabot, and secret-scanning alerts for the current repository. Secret values are never loaded.",
			[
				action("get_state", "Return radar blips and totals."),
				action("refresh", "Sync open alerts from GitHub for the current repository. Falls back to the last cached sync."),
				action("contain_finding", "Annotate one finding as contained for this repository only. Does not close alerts or change posture scores."),
				action("explain_finding", "Ask Copilot for a short, repo-grounded explanation shown in the panel."),
				action("assess_priority", "Propose a read-only, evidence-based AI triage priority in the discussion. Does not change GitHub severity or radar position; secrets use metadata only."),
				action("suggest_fix", "Ask Copilot for a short remediation strategy (no code) shown in the panel."),
				action("ask_copilot", "Ask Copilot a free-form question about one finding.", {
					question: { type: "string", maxLength: 500 },
				}),
				action("clear_thread", "Clear the Copilot answers for one finding."),
				action("request_copilot", "Launch a dedicated isolated worktree session to remediate one non-secret finding."),
				action("assign_copilot", "Assign one code scanning alert to Copilot Autofix (agentic) via the GitHub REST API. Uses AI credits."),
				action("reset_contains", "Clear containment marks."),
			],
		),
		defineCanvas(
			"compliance-scoreboard",
			"NIS2 / DORA score",
			"Illustrative NIS2 / DORA posture from the current repository's alerts and repo evidence, with Copilot-drafted plans. Not a legal assessment.",
			[
				action("get_state", "Return the five control themes, evidence, and scores."),
				action("refresh", "Re-sync alerts and security settings from GitHub."),
				action("toggle_preview", "Show or hide the projected score once critical and high findings are fixed."),
				action("preview_lift", "Show the projected score once critical and high findings are fixed."),
				action("clear_lift", "Hide the projected score."),
				action("generate_brief", "Build and save a uniquely named posture brief snapshot from live data."),
				action("close_brief", "Hide the posture brief cards."),
				action("fix_locally", "Launch a dedicated worktree session for a displayed non-secret finding (id) from a control theme (controlId). Without controlId, id is a theme and targets its first non-secret finding.", {
					controlId: { type: "string", minLength: 1 },
				}),
				action("assign_copilot", "Assign one displayed code scanning finding (id) from a control theme (controlId) to Copilot Autofix. Uses AI credits; does not change the posture score.", {
					controlId: { type: "string", minLength: 1 },
				}),
				action("assess_priority", "Assess a mapped finding in the selected control theme using read-only evidence. Advisory AI priority only; does not change posture scores.", {
					controlId: { type: "string", minLength: 1 },
				}),
				action("draft_plan", "Ask Copilot for a 30-day remediation plan for one control theme (id)."),
				action("draft_dependency_plan", "Draft an advisory upgrade plan for selected open dependency groups. Read-only: no campaign, upgrade execution or fix session.", {
					controlId: { type: "string", minLength: 1 },
					ids: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 1000, uniqueItems: true },
				}),
				action("draft_evidence", "Draft a read-only response-evidence checklist for the incident theme (id). Does not create documents or claim response capability."),
				action("draft_board", "Ask Copilot for a board summary of one control theme (id)."),
				action("ask_auditor", "Ask Copilot what evidence an auditor would want for one control theme (id)."),
				action("ask_copilot", "Ask Copilot a read-only governance question about one control theme (id). Fix execution stays in the radar.", {
					question: { type: "string", maxLength: 500 },
				}),
				action("clear_thread", "Clear the Copilot answers for one control theme (id)."),
			],
		),
	],
});

const localFixPath = join(artifactDir(), `local-fixes-${session.sessionId}.json`);
try {
	await chmod(localFixPath, 0o600);
	const restored = JSON.parse(await readFile(localFixPath, "utf8"));
	if (!restored || typeof restored !== "object" || Array.isArray(restored)) throw new Error("Invalid saved local fix state.");
	for (const record of Object.values(restored)) {
		if (!record || typeof record !== "object" || !record.requestId || !record.canvasId) throw new Error("Invalid saved local fix record.");
		if (typeof record.repo === "string") record.repo = record.repo.toLowerCase();
		if (record.status === "launching") {
			record.status = "unknown";
			record.error = "Extension reloaded before session launch was confirmed. Check the session sidebar before launching another fix.";
		}
	}
	world.localFixes = restored;
} catch (error) {
	if (error.code !== "ENOENT") {
		session.log(`Could not restore dedicated fix sessions: ${error.message}`, { level: "error" });
		throw new Error(`Cannot safely restore dedicated fix sessions: ${error.message}. Inspect the saved ledger before reloading.`);
	}
}
const localFixLauncher = createLocalFixLauncher({
	records: world.localFixes,
	parentSessionId: session.sessionId,
	send: (message) => session.send(message),
	persist: async () => {
		await mkdir(artifactDir(), { recursive: true });
		await privateWrite(`${localFixPath}.tmp`, JSON.stringify(world.localFixes, null, 2));
		await rename(`${localFixPath}.tmp`, localFixPath);
	},
	broadcast: () => broadcast("*"),
	log: (message) => session.log(message, { level: "error" }),
});

const campaignPath = join(artifactDir(), `campaigns-${session.sessionId}.json`);
const campaignData = { draft: null, receipts: [] };
try {
	const restored = JSON.parse(await readFile(campaignPath, "utf8"));
	if (!restored || !Array.isArray(restored.receipts)) throw new Error("Invalid saved campaign state.");
	Object.assign(campaignData, restored);
	for (const receipt of campaignData.receipts) {
		if (!receipt || !/^[\w.-]+\/[\w.-]+$/.test(receipt.repo) || typeof receipt.id !== "string") throw new Error("Invalid saved campaign receipt.");
		receipt.repo = receipt.repo.toLowerCase();
		if (receipt.status === "publishing") {
			receipt.status = "unknown";
			receipt.error = "Extension reloaded before publication was confirmed. Check publication; do not retry.";
		}
	}
	if (campaignData.draft) {
		if (typeof campaignData.draft.repo !== "string" || !REPO_PATTERN.test(campaignData.draft.repo)) throw new Error("Invalid saved campaign preparation.");
		campaignData.draft.repo = campaignData.draft.repo.toLowerCase();
	}
} catch (error) {
	if (error.code !== "ENOENT") {
		session.log(`Could not restore campaign state: ${error.message}`, { level: "error" });
		throw new Error(`Cannot safely restore campaign receipts: ${error.message}. Inspect the saved ledger before reloading.`);
	}
}
campaignService = createCampaignService({
	data: campaignData, context: campaignContext, api: campaignApi,
	list: (path) => ghPages(path, ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"]),
	persist: async (data) => {
		await mkdir(artifactDir(), { recursive: true });
		await writeFile(`${campaignPath}.tmp`, JSON.stringify(data, null, 2), { mode: 0o600 });
		await rename(`${campaignPath}.tmp`, campaignPath);
	},
	broadcast: () => broadcast("*"),
	log: (message) => session.log(message, { level: "error" }),
});

markSessionReady();

session.log("Security radar and NIS2 canvases ready", { ephemeral: true });
