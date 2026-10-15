import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

/**
 * Pure model for the attack surface radar and NIS2 / DORA posture canvases.
 * Findings are alert metadata and remediation notes. No exploit strings live here.
 */

export const DISCLAIMER =
	"Illustrative posture based on repository alert data. Not a legal assessment, not a penetration test, and not an exploit walkthrough.";

const WEIGHT = { critical: 8, high: 4, medium: 2, low: 1 };

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SOURCE_RANK = { "code-scanning": 3, "secret-scanning": 2, dependabot: 1 };
const RULE_SEVERITY = { error: "high", warning: "medium", note: "low" };
// Past this, single-package blips crowd the outer rings and the radar stops reading.
const MAX_PACKAGE_BLIPS = 14;

function slug(text) {
	return String(text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "item";
}

export function findingId(source, key) {
	return `${source}-${slug(key)}-${createHash("sha256").update(String(key)).digest("hex").slice(0, 24)}`;
}

function worst(severities) {
	return severities.reduce((top, sev) => ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[top] ?? 0) ? sev : top), "low");
}

function countSeverities(severities) {
	const out = { critical: 0, high: 0, medium: 0, low: 0 };
	for (const sev of severities) out[sev in out ? sev : "low"] += 1;
	return out;
}

function groupBy(items, key) {
	const groups = new Map();
	for (const item of items) {
		const k = key(item);
		if (!groups.has(k)) groups.set(k, []);
		groups.get(k).push(item);
	}
	return groups;
}

/** Generic remediation guidance per alert source; no repository-specific knowledge. */
function remediationFor(source, { rule = "", label = "", name = "", rollup = false } = {}) {
	if (source === "secret-scanning") {
		return `Revoke the ${label || "exposed credential"}, purge it from history, and turn on push protection. The value stays hidden.`;
	}
	if (source === "dependabot") {
		if (rollup) return "Batch the remaining dependency bumps after the high-severity packages.";
		return `Bump ${name || "the package"} to a patched version in the manifest or lockfile and rerun the test suite.`;
	}
	if (rule.startsWith("actions/")) {
		return "Fix the workflow: pin actions to a full commit SHA, pass untrusted data through environment variables, and set least-privilege permissions.";
	}
	return "Follow the rule guidance in code scanning, fix the flagged path, and add a test for it.";
}

/**
 * Turn raw GitHub alert payloads into radar findings: one blip per code-scanning
 * rule, per secret type, and per vulnerable package. Ids derive from the rule,
 * secret type, or ecosystem/package key so open threads survive a refresh.
 * Secret values are never read; only the type and alert number are used.
 */
export function buildLiveFindings({ code = [], dependabot = [], secrets = [], defaultBranch } = {}) {
	const out = [];

	for (const [ruleId, alerts] of groupBy(code, (a) => a.rule?.id ?? "unknown")) {
		const id = findingId("cs", ruleId);
		const severities = alerts.map((a) => a.rule?.security_severity_level || RULE_SEVERITY[a.rule?.severity] || "medium");
		const locations = alerts
			.sort((a, b) => (a.number ?? 0) - (b.number ?? 0))
			.map((a) => a.most_recent_instance?.location ?? {})
			.filter((loc) => loc.path);
		const loc = locations[0] ?? {};
		const remainder = typeof defaultBranch === "string" ? alerts.filter(
			(a) => a.most_recent_instance?.ref !== `refs/heads/${defaultBranch}`,
		) : null;
		out.push({
			id,
			source: "code-scanning",
			severity: worst(severities),
			rule: ruleId,
			title: alerts[0].rule?.description ?? ruleId,
			path: loc.path ?? "Code scanning",
			line: loc.start_line ?? null,
			count: alerts.length,
			...(remainder ? {
				campaignCount: alerts.length - remainder.length,
				campaignRemainder: { count: remainder.length, severity: worst(remainder.map(
					(a) => a.rule?.security_severity_level || RULE_SEVERITY[a.rule?.severity] || "medium",
				)) },
			} : {}),
			htmlUrl: alerts.length === 1 ? alerts[0].html_url ?? null : null,
			copilot: (() => {
				const representative = pickRadarAlert(alerts, { rule: ruleId, path: loc.path, line: loc.start_line });
				return representative && (representative.assignees ?? []).some((u) => isCopilotLogin(u.login))
					? { number: representative.number, url: representative.html_url } : null;
			})(),
			bySeverity: countSeverities(severities),
			controlIds: !ruleId.startsWith("actions/") ? ["vuln"] : ruleId.includes("unpinned") ? ["change", "supply"] : ["change"],
			remediation: remediationFor("code-scanning", { rule: ruleId }),
		});
	}

	for (const [type, alerts] of groupBy(secrets, (a) => a.secret_type ?? "unknown")) {
		const id = findingId("sec", type);
		const numbers = alerts.map((a) => a.number).filter(Boolean).sort((a, b) => a - b);
		const label = alerts[0].secret_type_display_name || type;
		out.push({
			id,
			source: "secret-scanning",
			campaignSelector: type,
			severity: "high",
			rule: slug(type),
			title: `${label} alert`,
			path: numbers.length ? `Secret scanning alert${numbers.length > 1 ? "s" : ""} #${numbers.join(", #")}` : "Secret scanning",
			line: null,
			count: alerts.length,
			campaignCount: alerts.length,
			htmlUrl: alerts.length === 1 ? alerts[0].html_url ?? null : null,
			bySeverity: countSeverities(alerts.map(() => "high")),
			controlIds: ["secrets"],
			remediation: remediationFor("secret-scanning", { label }),
		});
	}

	const packages = [];
	for (const [key, alerts] of groupBy(dependabot, (a) => `${a.dependency?.package?.ecosystem ?? "npm"}/${a.dependency?.package?.name ?? "unknown"}`)) {
		const name = alerts[0].dependency?.package?.name ?? key;
		const severities = alerts.map((a) => a.security_advisory?.severity || "medium");
		const manifests = [...groupBy(alerts, (a) => a.dependency?.manifest_path ?? "lockfile")]
			.sort((a, b) => b[1].length - a[1].length)
			.map(([path]) => path);
		const id = findingId("dep", key);
		packages.push({
			id,
			source: "dependabot",
			severity: worst(severities),
			rule: key,
			title: `${name} dependency alerts`,
			path: manifests.join(", "),
			line: null,
			count: alerts.length,
			htmlUrl: alerts.length === 1 ? alerts[0].html_url ?? null : null,
			bySeverity: countSeverities(severities),
			controlIds: ["supply"],
			remediation: remediationFor("dependabot", { name }),
		});
	}
	packages.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count || a.id.localeCompare(b.id));
	const named = [];
	const rest = [];
	for (const pkg of packages) {
		const notable = SEVERITY_RANK[pkg.severity] >= SEVERITY_RANK.high || pkg.count >= 3;
		(notable && named.length < MAX_PACKAGE_BLIPS ? named : rest).push(pkg);
	}
	if (rest.length === 1) named.push(rest.pop());
	out.push(...named);
	if (rest.length) {
		const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
		for (const pkg of rest) for (const sev of Object.keys(bySeverity)) bySeverity[sev] += pkg.bySeverity[sev];
		out.push({
			id: "dep-rest",
			source: "dependabot",
			severity: worst(rest.map((pkg) => pkg.severity)),
			rule: "dependabot-rollup",
			title: "Other open dependency alerts",
			path: [...new Set(rest.flatMap((pkg) => pkg.path.split(", ")))].join(", "),
			line: null,
			count: rest.reduce((sum, pkg) => sum + pkg.count, 0),
			packages: rest.length,
			packageNames: rest.map((pkg) => pkg.rule.split("/").slice(1).join("/")),
			bySeverity,
			controlIds: ["supply"],
			remediation: remediationFor("dependabot", { rollup: true }),
		});
	}

	return out.sort(
		(a, b) =>
			SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
			SOURCE_RANK[b.source] - SOURCE_RANK[a.source] ||
			b.count - a.count ||
			a.id.localeCompare(b.id),
	);
}

/** Keep only the alert fields the radar needs. Secret values and snippets are dropped. */
export function stripAlerts({ code = [], dependabot = [], secrets = [] } = {}) {
	return {
		code: code.map((a) => ({
			number: a.number,
			html_url: a.html_url,
			assignees: (a.assignees ?? []).map((u) => ({ login: u.login })),
			rule: {
				id: a.rule?.id,
				severity: a.rule?.severity,
				security_severity_level: a.rule?.security_severity_level,
				description: a.rule?.description,
			},
			most_recent_instance: {
				ref: a.most_recent_instance?.ref,
				location: { path: a.most_recent_instance?.location?.path, start_line: a.most_recent_instance?.location?.start_line },
			},
		})),
		dependabot: dependabot.map((a) => ({
			number: a.number,
			html_url: a.html_url,
			dependency: {
				package: { ecosystem: a.dependency?.package?.ecosystem, name: a.dependency?.package?.name },
				manifest_path: a.dependency?.manifest_path,
			},
			security_advisory: { severity: a.security_advisory?.severity },
		})),
		secrets: secrets.map((a) => ({
			number: a.number,
			html_url: a.html_url,
			secret_type: a.secret_type,
			secret_type_display_name: a.secret_type_display_name,
		})),
	};
}

export function radarTotals(raw, asOf) {
	return {
		codeScanning: raw.code?.length ?? 0,
		dependabot: raw.dependabot?.length ?? 0,
		secretScanning: raw.secrets?.length ?? 0,
		asOf,
	};
}

export const EMPTY_TOTALS = { codeScanning: 0, dependabot: 0, secretScanning: 0, asOf: null };

// Illustrative mapping only. Article numbers follow NIS2 (EU 2022/2555) and DORA (EU 2022/2554).
export const CONTROLS = [
	{
		id: "vuln",
		title: "Vulnerability handling",
		nis2: ["Art. 21(2)(e)"],
		dora: ["Art. 9(4)(e)", "Art. 25(1)"],
		summary: "Code-scanning findings need an owner, a fix, and proof the alert closed.",
	},
	{
		id: "supply",
		title: "Supply-chain risk",
		nis2: ["Art. 21(2)(d)"],
		dora: ["Art. 9(4)(f)", "Art. 28"],
		summary: "Vulnerable open-source packages are third-party code. Patch them, and track ICT providers under DORA Art. 28.",
	},
	{
		id: "secrets",
		title: "Secrets and access",
		nis2: ["Art. 21(2)(i)", "Art. 21(2)(j)"],
		dora: ["Art. 9(4)(c)", "Art. 9(4)(d)"],
		summary: "Exposed credentials must be revoked and rotated. Push protection blocks the next one at git push.",
	},
	{
		id: "change",
		title: "Secure change control",
		nis2: ["Art. 21(2)(e)"],
		dora: ["Art. 9(4)(e)"],
		summary: "Workflow permissions, pinned actions, and reviewed changes are change-management evidence.",
	},
	{
		id: "incident",
		title: "Incident response evidence",
		nis2: ["Art. 21(2)(b)", "Art. 23"],
		dora: ["Art. 17", "Art. 19"],
		summary: "Do we have a security contact and a documented response and reporting process? This theme checks repository evidence, not an active incident.",
		clock: true,
	},
];

export const APPLICABILITY =
	"DORA sets direct obligations for EU financial entities and an oversight framework for designated critical ICT third-party providers. NIS2 scope depends on sector, size, and national transposition.";

/**
 * Repository evidence the scoreboard checks. Files are looked up in the checkout;
 * settings come from the GitHub repository security_and_analysis block.
 */
export const EVIDENCE = [
	{ id: "codeql", short: "CodeQL", label: "CodeQL code scanning workflow", controlIds: ["vuln", "incident"], paths: [".github/workflows/codeql-advanced.yml", ".github/workflows/codeql.yml"] },
	{ id: "security-md", short: "SECURITY.md", label: "SECURITY.md disclosure policy", controlIds: ["vuln", "incident"], paths: ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"] },
	{ id: "dependabot-config", short: "Dependabot config", label: "Dependabot update config", controlIds: ["supply"], paths: [".github/dependabot.yml", ".github/dependabot.yaml"] },
	{ id: "dependabot-updates", short: "Dependabot updates", label: "Dependabot security updates", controlIds: ["supply"], setting: "dependabot_security_updates" },
	{ id: "push-protection", short: "Push protection", label: "Secret push protection", controlIds: ["secrets"], setting: "secret_scanning_push_protection" },
	{ id: "validity-checks", short: "Validity checks", label: "Secret validity checks", controlIds: ["secrets"], setting: "secret_scanning_validity_checks" },
	{ id: "codeowners", short: "CODEOWNERS", label: "CODEOWNERS ownership map", controlIds: ["change"], paths: ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] },
	{ id: "runbook", short: "Runbook", label: "Incident response runbook", controlIds: ["incident"], paths: ["docs/incident-response.md", "docs/runbooks/incident.md", "INCIDENT_RESPONSE.md", ".github/INCIDENT_RESPONSE.md"] },
];

export const EVIDENCE_SOURCE_LABEL = {
	checkout: "repo file",
	live: "live setting",
	cached: "cached setting",
	unknown: "setting not readable",
};

/** Resolve each evidence item to true, false, or null (unknown). */
export function repoEvidence(exists, settings = null) {
	const out = {};
	for (const item of EVIDENCE) {
		if (item.paths) out[item.id] = item.paths.some((path) => exists(path));
		else {
			const status = settings?.[item.setting]?.status;
			out[item.id] = status === "enabled" ? true : status === "disabled" ? false : null;
		}
	}
	return out;
}

export const NIS2_CLOCK = [
	{ at: "24 h", label: "Early warning", note: "Suspected malicious or cross-border impact" },
	{ at: "72 h", label: "Incident notification", note: "Initial assessment, severity, indicators" },
	{ at: "1 month", label: "Final report", note: "Root cause, mitigations, cross-border impact" },
];
export const DORA_CLOCK = ["Classify as major (Art. 18)", "Initial, intermediate, final report (Art. 19)", "Deadlines set by the DORA reporting RTS"];

const BANNED = ["OR 1=1", "DROP TABLE", "ghp_", "xoxb-", "<script>alert", "union select"];

export function escapeHtml(value) {
	return String(value ?? "").replace(/[&<>"']/g, (char) => ({
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		'"': "&quot;",
		"'": "&#39;",
	})[char]);
}

/** Percent of the radar box, from the center. Must match the SVG rings in pages.mjs. */
export const RING_RADIUS = { critical: 18, high: 32, medium: 44, low: 46 };

const RING_NAME = { critical: "inner ring", high: "middle ring", medium: "outer ring", low: "outer edge" };

export function findingBrief(finding) {
	if (!finding) return { filePath: null, what: "", where: "", why: "", ring: "outer ring" };
	const ring = RING_NAME[finding.severity] ?? "outer ring";
	const why = `${finding.severity} severity, so it sits on the ${ring}. Closer to the center means higher severity.`;
	if (finding.id === "dep-rest") {
		const spread = finding.packages ? ` across ${finding.packages} lower-priority packages` : "";
		const names = finding.packageNames?.length ? ` Packages: ${finding.packageNames.slice(0, 8).join(", ")}${finding.packageNames.length > 8 ? ", and more" : ""}.` : "";
		return {
			filePath: null,
			ring,
			what: `${finding.count} remaining dependency alerts${spread}, rolled up so the radar stays readable. Handle the named high packages first.${names}`,
			where: `Manifests: ${finding.path}. This blip is a rollup, not one package.`,
			why,
		};
	}
	if (finding.source === "dependabot") {
		const name = String(finding.rule ?? "").split("/").slice(1).join("/") || finding.title;
		return {
			filePath: finding.path,
			ring,
			what: `${finding.count} open Dependabot alert${finding.count === 1 ? "" : "s"} on the package ${name}. A vulnerable version is in use, so the fix is a dependency bump rather than a code change.`,
			where: `Manifest ${finding.path}. Package ${name}. Advisory text is not loaded onto this screen.`,
			why,
		};
	}
	if (finding.source === "secret-scanning") {
		return {
			filePath: null,
			ring,
			what: `Secret scanning found ${finding.count} exposed credential${finding.count === 1 ? "" : "s"} (${finding.title.replace(/ alert$/, "")}). The value is never loaded into this canvas and must not be shared.`,
			where: `${finding.path}. No file path is shown so the secret text stays out of view.`,
			why,
		};
	}
	return {
		filePath: finding.line ? finding.path : null,
		ring,
		what: `Code scanning rule ${finding.rule} flagged ${finding.count} location${finding.count === 1 ? "" : "s"}. ${finding.remediation}`,
		where: finding.line ? `${finding.path} around line ${finding.line}.` : finding.path,
		why,
	};
}

function hashUnit(text) {
	let h = 2166136261;
	for (let i = 0; i < text.length; i += 1) {
		h ^= text.charCodeAt(i);
		h = Math.imul(h, 16777619);
	}
	return (h >>> 0) / 4294967296;
}

// Scatter inside the severity band. Equal steps on the ring read as a diagram.
const RADIAL_BAND = {
	critical: [14.2, 20.8],
	high: [24.4, 36.6],
	medium: [40.6, 44.2],
	low: [45, 46.2],
};

// The seed only moves bearings. Radius stays tied to the id and its severity
// band, so a reshuffle never changes how hot a finding looks.
function ringPlacement(group, seed = 0) {
	const spin = (text) => hashUnit(seed ? `${seed}|${text}` : text);
	const placed = new Map();
	const [lo, hi] = RADIAL_BAND[group[0].severity] ?? RADIAL_BAND.medium;
	if (group.length === 1) {
		const id = group[0].id;
		placed.set(id, {
			angle: spin(`${id}:ang`) * Math.PI * 2,
			radius: lo + hashUnit(`${id}:r`) * (hi - lo),
		});
		return placed;
	}
	// More spokes than contacts, so some arcs stay empty. A full ring of equal
	// steps reads as a diagram; a radar picture has holes and uneven bearings.
	const spokes = group.length + Math.max(2, Math.ceil(group.length * 0.45));
	// Spread contacts over the whole ring; hashing straight to a spoke clumps
	// them on one side. Order by hash so ids keep stable bearings.
	const used = new Set();
	const spokeOf = new Map();
	const order = [...group].sort((x, y) => spin(`${x.id}:spoke`) - spin(`${y.id}:spoke`));
	const offset = spin(`${group[0].severity}:offset`);
	order.forEach((finding, index) => {
		const spoke = Math.floor((index + offset) * (spokes / group.length)) % spokes;
		used.add(spoke);
		spokeOf.set(finding.id, spoke);
	});
	const weights = Array.from({ length: spokes }, (_, index) => {
		const wrapped = (spin(`${group[0].severity}:spoke:${index}`) * 5.31) % 1;
		return used.has(index) ? 0.42 + wrapped * 0.7 : 0.85 + wrapped * 1.35;
	});
	const sum = weights.reduce((total, weight) => total + weight, 0);
	let cursor = spin(`${group[0].severity}:phase`) * Math.PI * 2;
	const center = new Array(spokes);
	for (let index = 0; index < spokes; index += 1) {
		const span = (weights[index] / sum) * Math.PI * 2;
		center[index] = cursor + span * (0.38 + spin(`${group[0].severity}:mid:${index}`) * 0.24);
		cursor += span;
	}
	for (const finding of group) {
		const spoke = spokeOf.get(finding.id);
		placed.set(finding.id, {
			angle: center[spoke] + (spin(`${finding.id}:jit`) - 0.5) * 0.22,
			radius: lo + hashUnit(`${finding.id}:r`) * (hi - lo),
		});
	}
	// Close bearings with the same radius read as a bead on the ring. Split them
	// radially so a pair becomes a cluster, not an overlap.
	const ordered = [...group].sort((a, b) => placed.get(a.id).angle - placed.get(b.id).angle);
	for (let index = 0; index < ordered.length; index += 1) {
		const a = placed.get(ordered[index].id);
		const b = placed.get(ordered[(index + 1) % ordered.length].id);
		let gap = b.angle - a.angle;
		if (gap < 0) gap += Math.PI * 2;
		if (gap > 0.34 || Math.abs(a.radius - b.radius) >= 5.5) continue;
		const mid = (a.radius + b.radius) / 2;
		const half = Math.max(3.4, (hi - lo) * 0.28);
		a.radius = Math.max(lo, Math.min(hi, mid - half));
		b.radius = Math.max(lo, Math.min(hi, mid + half));
	}
	return placed;
}

const MIN_BLIP_GAP = 6.5;

function closestGap(placed) {
	const points = [...placed.values()].map((spot) => [Math.cos(spot.angle) * spot.radius, Math.sin(spot.angle) * spot.radius]);
	let gap = Infinity;
	for (let i = 0; i < points.length; i += 1) {
		for (let j = i + 1; j < points.length; j += 1) {
			gap = Math.min(gap, Math.hypot(points[i][0] - points[j][0], points[i][1] - points[j][1]));
		}
	}
	return gap;
}

export function layoutFindings(findings = [], seed = 0) {
	const groups = new Map();
	for (const finding of findings) {
		const key = finding.severity;
		if (!groups.has(key)) groups.set(key, []);
		groups.get(key).push(finding);
	}
	const placeAll = (salt) => {
		const placed = new Map();
		for (const group of groups.values()) {
			for (const [id, spot] of ringPlacement(group, salt)) placed.set(id, spot);
		}
		return placed;
	};
	let placed = placeAll(seed);
	// Random bearings can stack blips from neighbouring rings. Retry derived
	// seeds until every pair has room, keeping the roomiest try as a fallback.
	if (seed) {
		let best = placed;
		let bestGap = closestGap(placed);
		for (let attempt = 1; attempt < 40 && bestGap < MIN_BLIP_GAP; attempt += 1) {
			const next = placeAll(seed * 31 + attempt);
			const gap = closestGap(next);
			if (gap > bestGap) {
				best = next;
				bestGap = gap;
			}
		}
		placed = best;
	}
	return findings.map((finding) => {
		const spot = placed.get(finding.id);
		const brief = findingBrief(finding);
		return {
			...finding,
			...brief,
			angle: spot.angle,
			radius: spot.radius,
			x: 50 + Math.cos(spot.angle) * spot.radius,
			y: 50 + Math.sin(spot.angle) * spot.radius,
		};
	});
}

function deduction(finding) {
	if (finding.source === "secret-scanning") return 8;
	if (finding.source === "dependabot" && finding.id !== "dep-rest") {
		if (finding.count >= 20) return 3;
		if (finding.count >= 8) return 2;
		return 1;
	}
	if (finding.id === "dep-rest") return 2;
	const base = WEIGHT[finding.severity] ?? 1;
	const extra = finding.count > 1 ? Math.min(4, Math.floor((finding.count - 1) / 3)) : 0;
	return base + extra;
}

const GAP_PENALTY = 4;

/** Plain-language scoring legend shown under the gauge; built from the same weights the score uses. */
export const SCORING_LEGEND = [
	{ label: "Critical rule", points: -WEIGHT.critical },
	{ label: "High rule", points: -WEIGHT.high },
	{ label: "Medium rule", points: -WEIGHT.medium },
	{ label: "Repeats", points: "−1 per 3 more, max −4" },
	{ label: "Exposed secret", points: -8 },
	{ label: "Vulnerable package", points: "−1 to −3" },
	{ label: "Missing evidence", points: -GAP_PENALTY },
	{ label: "Unknown evidence", points: "0" },
];
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

function asSet(ids) {
	return ids instanceof Set ? ids : new Set(ids);
}

function openFor(control, findings, contained) {
	return findings.filter((finding) => finding.controlIds.includes(control.id) && !contained.has(finding.id));
}

function evidenceFor(control, evidence, sources = {}) {
	return EVIDENCE.filter((item) => item.controlIds.includes(control.id)).map((item) => ({
		id: item.id,
		short: item.short,
		label: item.label,
		status: evidence?.[item.id] ?? null,
		source: sources[item.id] ?? (item.paths ? "checkout" : "unknown"),
	}));
}

export function scoreControl(control, findings, containedIds, evidence = {}) {
	const contained = asSet(containedIds);
	const lost = openFor(control, findings, contained).reduce((sum, finding) => sum + deduction(finding), 0);
	const gaps = evidenceFor(control, evidence).filter((item) => item.status === false).length;
	return clamp(20 - lost - gaps * GAP_PENALTY, 0, 20);
}

/** Every critical or high finding group, from any source: what the "once critical & high are fixed" projection closes. */
export function criticalHighIds(findings = []) {
	return findings.filter((finding) => SEV_ORDER[finding.severity] >= SEV_ORDER.high).map((finding) => finding.id);
}

export const REPO_PATTERN = /^[\w.-]+\/[\w.-]+$/;

// "owner/name" from an https, ssh or scp-style git remote URL; null when it does not look like one.
export function parseRemoteRepo(url) {
	if (typeof url !== "string") return null;
	const match = url.trim().match(/^(?:[\w+.-]+:\/\/(?:[^@/]+@)?[^/]+\/|[^@\s/]+@[^:\s/]+:)([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/);
	const repo = match ? `${match[1]}/${match[2]}` : null;
	return repo && REPO_PATTERN.test(repo) ? repo : null;
}

export function alertUrl(finding, repo) {
	if (!repo) return null;
	const base = `https://github.com/${repo}/security`;
	if (finding.source === "secret-scanning") return `${base}/secret-scanning`;
	if (finding.source === "dependabot") {
		if (finding.id === "dep-rest") return `${base}/dependabot`;
		const name = String(finding.rule || "").split("/").slice(1).join("/") || finding.title.replace(/ dependency alerts$/, "");
		return `${base}/dependabot?q=${encodeURIComponent(`is:open package:${name}`)}`;
	}
	return `${base}/code-scanning?query=${encodeURIComponent(`is:open rule:${finding.rule}`)}`;
}

function slimFinding(finding, repo) {
	return {
		id: finding.id,
		title: finding.title,
		source: finding.source,
		severity: finding.severity,
		count: finding.count,
		where: finding.line ? `${finding.path}:${finding.line}` : finding.path,
		url: alertUrl(finding, repo),
		copilot: finding.copilot ?? null,
	};
}

export function complianceModel(containedIds = [], findings = [], options = {}) {
	const { totals = EMPTY_TOTALS, evidence = {}, evidenceSource = {}, repo = null } = options;
	const contained = asSet(containedIds);
	const fixed = new Set([...contained, ...criticalHighIds(findings)]);
	const controls = CONTROLS.map((control) => {
		const open = openFor(control, findings, contained).sort(
			(a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity] || b.count - a.count || a.id.localeCompare(b.id),
		);
		const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
		for (const finding of open) {
			if (finding.bySeverity) for (const sev of Object.keys(bySeverity)) bySeverity[sev] += finding.bySeverity[sev] ?? 0;
			else bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + finding.count;
		}
		return {
			...control,
			framework: `NIS2 ${control.nis2.join(", ")} · DORA ${control.dora.join(", ")}`,
			score: scoreControl(control, findings, contained, evidence),
			projectedScore: scoreControl(control, findings, fixed, evidence),
			scoreDetails: {
				alertPenalty: open.reduce((sum, finding) => sum + deduction(finding), 0),
				evidencePenalty: evidenceFor(control, evidence).filter((item) => item.status === false).length * GAP_PENALTY,
			},
			scoreCeiling: 20 - evidenceFor(control, evidence).filter((item) => item.status === false).length * GAP_PENALTY,
			campaignFindings: open.map((finding) => ({
				id: finding.id, source: finding.source, count: finding.count,
				campaignCount: finding.campaignCount ?? null,
				deduction: deduction(finding),
				campaignDeduction: finding.campaignRemainder?.count
					? deduction(finding) - deduction({ ...finding, ...finding.campaignRemainder })
					: deduction(finding),
			})),
			open: open.length,
			alerts: open.reduce((sum, finding) => sum + finding.count, 0),
			bySeverity,
			findings: open.slice(0, 6).map((finding) => slimFinding(finding, repo)),
			more: Math.max(0, open.length - 6),
			evidence: evidenceFor(control, evidence, evidenceSource),
		};
	});
	const score = controls.reduce((sum, control) => sum + control.score, 0);
	const projected = controls.reduce((sum, control) => sum + control.projectedScore, 0);
	return {
		score,
		projected,
		lift: projected - score,
		controls,
		contained: [...contained],
		totals,
		repo,
		clock: { nis2: NIS2_CLOCK, dora: DORA_CLOCK },
		applicability: APPLICABILITY,
		scoring: SCORING_LEGEND,
		disclaimer: DISCLAIMER,
	};
}

/** Self-contained so the browser and model tests use exactly the same projection. */
export function remediationProjection(controls, selectedIds, mode = "campaign") {
	if (!["campaign", "dependencies"].includes(mode)) throw new Error("Choose a campaign or dependency-plan projection.");
	const selected = new Set(selectedIds);
	const groups = new Map();
	const scores = controls.map((control) => {
		let remaining = 0;
		for (const finding of control.campaignFindings ?? []) {
			const included = selected.has(finding.id) && (mode === "dependencies"
				? finding.source === "dependabot" : ["code-scanning", "secret-scanning"].includes(finding.source));
			remaining += finding.deduction - (included ? mode === "dependencies" ? finding.deduction : finding.campaignDeduction : 0);
			if (included) groups.set(finding.id, finding);
		}
		const projected = control.campaignFindings
			? Math.max(control.score, Math.min(20, Math.max(0, control.scoreCeiling - remaining)))
			: control.score;
		return { id: control.id, score: projected, lift: projected - control.score };
	});
	const findings = [...groups.values()];
	const score = scores.reduce((sum, control) => sum + control.score, 0);
	return {
		controls: scores, score,
		lift: scores.reduce((sum, control) => sum + control.lift, 0),
		groups: findings.length,
		alerts: findings.reduce((sum, finding) => sum + (mode === "dependencies" ? finding.count : finding.campaignCount ?? finding.count), 0),
		excluded: mode === "dependencies" ? 0 : findings.reduce((sum, finding) => sum + (finding.campaignCount == null ? 0 : finding.count - finding.campaignCount), 0),
		upperBound: mode !== "dependencies" && findings.some((finding) => finding.campaignCount == null),
	};
}

export function campaignProjection(controls, selectedIds) {
	return remediationProjection(controls, selectedIds);
}

export const COMPLIANCE_ASK_KINDS = ["plan", "board", "auditor", "ask", "dependencies", "evidence"];
export const COMPLIANCE_ASK_LABEL = {
	plan: "Draft a 30-day remediation plan",
	board: "Write the board summary",
	auditor: "What will an auditor ask for?",
	dependencies: "Draft a dependency upgrade plan",
	evidence: "Draft a response-evidence checklist",
};

const COMPLIANCE_TASK = {
	plan: [
		"Task: draft a 30-day remediation plan for this control theme in at most 90 words.",
		"Give 3 or 4 bullets starting with '- '. Each bullet: the action, the owner role, and the GitHub evidence that proves it is done (closed alert, merged pull request, setting enabled).",
		"Start with the highest-severity open finding. Mention Copilot Autofix or Copilot coding agent where it can draft the change.",
	],
	board: [
		"Task: write a board-level summary of this control theme in at most 70 words.",
		"Three short sentences: the exposure in business terms, what is already in place, and the decision or budget needed. No jargon, no rule ids.",
		"Present the regulatory reference as illustrative, not as a legal finding.",
	],
	auditor: [
		"Task: list what an auditor or supervisor would ask to see for this control theme, in at most 80 words.",
		"Give 3 or 4 bullets starting with '- '. For each, say whether this repository already evidences it and where on GitHub it would come from.",
	],
	dependencies: [
		"Task: draft a 30-day upgrade plan for ONLY the selected dependency groups listed above, in at most 120 words.",
		"Give 3 or 4 bullets: prioritize the highest-risk groups, batch compatible upgrades, name an owner role and target week, and require CI plus closed Dependabot alerts as proof.",
		"Use Dependabot alerts and pull requests. This is an advisory upgrade plan, NOT a GitHub Security Campaign.",
		"Do not invent fixed versions, existing pull requests, campaign progress, or verified compatibility. Flag missing information that must be checked in GitHub.",
	],
	evidence: [
		"Task: draft a response-evidence checklist in at most 100 words, grounded in the checked artifacts above.",
		"Prioritize a security contact/disclosure policy and a documented response/reporting runbook; distinguish already found, not found in this checkout, and unknown evidence.",
		"Give owner roles and validation steps, including a tabletop exercise and reporting escalation. File presence does not prove response capability.",
		"This is advice only. Do not create files, initiate a response, or assert a significant incident or a reporting obligation.",
	],
	ask: ["Task: answer the user's question below in at most 80 words, grounded in this control theme and repository."],
};

export function compliancePrompt(kind, control, model, question = "") {
	const task = COMPLIANCE_TASK[kind];
	if (!task) throw new Error(`unknown compliance prompt ${kind}`);
	const findings = control.findings.length
		? control.findings.map((f) => `${f.title} (${f.severity}, ${f.count} alert${f.count === 1 ? "" : "s"}, ${f.where})`).join("; ")
		: "none open";
	const evidence = control.evidence
		.map((item) => `${item.label}: ${item.status === true ? "in place" : item.status === false ? "missing" : "unknown"}`)
		.join("; ");
	const lines = [
		`NIS2 / DORA posture canvas on ${repoLabel(model.repo)}.`,
		`Control theme: ${control.title}. Illustrative mapping ${control.framework}. Illustrative score ${control.score}/20${kind === "dependencies" || kind === "evidence" ? "; no improvement has been achieved by this plan" : `, ${control.projectedScore}/20 once critical and high findings are fixed`}.`,
		`Data source: ${model.source === "github" ? "live GitHub metadata" : model.source === "cache" ? "cached GitHub metadata" : "no GitHub data synced yet"}.`,
		`Open findings mapped here (${control.alerts} alert${control.alerts === 1 ? "" : "s"}): ${findings}${control.more ? `; plus ${control.more} more` : ""}.`,
		`Repository evidence: ${evidence || "none checked"}.`,
		`Context: ${control.summary} ${model.applicability}`,
		"Answer from this context only. Do not call any tools. This is not a legal assessment.",
		"Planning only: do not create sessions, campaigns, issues or pull requests, execute upgrades, or change settings. Technical implementation belongs in the radar.",
		...task,
	];
	if (kind === "ask") lines.push(`Question: ${String(question).trim().slice(0, 500)}`);
	lines.push(
		"Reply right away in English with only the answer text. It is rendered inside a small side panel, so no headings, no tables, no code blocks.",
		"Do not include attack strings, payloads, secret values, or a proof of concept. Do not edit files.",
	);
	return lines.join("\n");
}

function firstStep(finding) {
	if (finding.source === "secret-scanning") return `revoke and rotate the ${finding.title.replace(/ alert$/, "")} (${finding.where}); evidence is the resolved alert.`;
	if (finding.source === "dependabot") return `merge the Dependabot update for ${finding.title.replace(/ dependency alerts$/, "")}; evidence is the closed alerts.`;
	return `fix ${finding.title} (${finding.where}) with Copilot Autofix; evidence is the closed alert.`;
}

export function complianceOfflineAnswer(kind, control) {
	const top = control.findings[0];
	const missing = control.evidence.filter((item) => item.status === false).map((item) => item.label);
	const unknown = control.evidence.filter((item) => item.status !== true && item.status !== false).map((item) => item.label);
	if (kind === "dependencies") return [
		`- Week 1, application owner: review the selected groups (${control.findings.map((f) => f.title).join(", ")}) in Dependabot; verify available fixes and compatible versions.`,
		"- Weeks 2–3, maintainers: review dependency update PRs in compatible batches and run API/frontend CI.",
		"- Week 4, security owner: refresh the alerts and retain merged PRs plus closed alerts as evidence. This offline checklist verifies no versions or fixes and creates no campaign.",
	].join("\n");
	if (kind === "evidence") return [
		missing.length ? `- Security owner: document and review ${missing.join(" and ")}; not found in the checked repository locations.` : "- Security owner: review the artifacts found in this checkout.",
		"- Response lead: define the contact, escalation path, owners and reporting process; exercise them in a tabletop.",
		"- Retain approved documents and exercise records as evidence. File presence alone does not demonstrate response capability; this checklist creates no files.",
	].join("\n");
	if (kind === "plan") {
		return [
			top ? `- Week 1: ${firstStep(top)}` : "- Week 1: confirm no open alerts remain on this theme.",
			missing.length ? `- Week 2: add ${missing.join(" and ")}; evidence is the merged pull request.` : unknown.length ? `- Week 2: verify ${unknown.join(" and ")}; their status is unknown.` : "- Week 2: keep the existing controls enabled and reviewed.",
			"- Week 3–4: burn down the remaining alerts and export the security overview as evidence.",
		].join("\n");
	}
	if (kind === "board") {
		return `${control.title} scores ${control.score}/20 today with ${control.alerts} open alert${control.alerts === 1 ? "" : "s"}. Fixing the critical and high findings lifts it to ${control.projectedScore}/20. ${missing.length ? `The gap to close next: ${missing.join(", ")}.` : ""}${unknown.length ? ` Unverified supporting controls (unknown status): ${unknown.join(", ")}.` : !missing.length ? "The supporting controls are in place." : ""}`;
	}
	if (kind === "auditor") {
		return control.evidence
			.map((item) => `- ${item.label}: ${item.status === true ? "evidenced in the repo settings or files" : item.status === false ? "not evidenced yet" : "not checked"}`)
			.concat(["- Alert history showing time to remediate, exported from GitHub security overview"])
			.join("\n");
	}
	return `Live Copilot did not answer in time. ${control.summary}`;
}

export function copilotPromptForFinding(finding, repo = null) {
	const brief = findingBrief(finding);
	return [
		`Remediation request on ${repoLabel(repo)}.`,
		`GitHub alert metadata: ${finding.title} (${finding.rule}), ${finding.path}${finding.line ? `:${finding.line}` : ""}, count ${finding.count}, severity ${finding.severity}.`,
		`Where: ${brief.where}`,
		`What it is: ${brief.what}`,
		`Remediation intent: ${finding.remediation}`,
		"Do not include attack strings, secret values, or a proof of concept.",
		"If you change code, keep the fix minimal and summarize it in two sentences a teammate can follow.",
	].join("\n");
}

export function explainPromptForFinding(finding, repo = null) {
	const brief = findingBrief(finding);
	const open = brief.filePath
		? `Open ${brief.filePath}${finding.line ? ` near line ${finding.line}` : ""} and explain the finding in plain English. Do not paste the vulnerable snippet.`
		: "There is no source file to open. Explain the alert from metadata only. Do not look up or display a secret value.";
	return [
		`Finding walkthrough on ${repoLabel(repo)}.`,
		`Finding: ${finding.title} (${finding.rule}), severity ${finding.severity}, ${finding.count} alert(s).`,
		`Where: ${brief.where}`,
		`What it is: ${brief.what}`,
		open,
		`It sits on the ${brief.ring} because closer to the center of the radar means higher severity.`,
		`Fix intent: ${finding.remediation}`,
		"Do not include attack strings, secret values, or a proof of concept.",
		"Do not run the application. Summarize in four short sentences a teammate can follow.",
	].join("\n");
}

export const RADAR_ASK_KINDS = ["explain", "assess", "fix", "ask"];

const RADAR_TASK = {
	explain: [
		"Task: explain this vulnerability to a security leader in at most 70 words.",
		"Ground it in this repository: name the file, function or package involved and what data or flow is at risk.",
		"Two or three short sentences. End with the business impact in one sentence.",
	],
	assess: [
		"Task: propose a contextual remediation priority for this existing alert, not a new vulnerability review.",
		"Use at most 140 words in four short bullets: Priority (Urgent/High/Normal/Low, or Unknown if evidence is insufficient); Evidence; Confidence (High/Medium/Low) and gaps; Next check.",
		"Assess input-to-operation reachability, authentication/authorization and validation controls, affected data and business impact. Cite repository file:line evidence for factual claims.",
		"Distinguish observed facts from assumptions. A static code path does not prove production exposure or exploitability; missing evidence is not evidence of safety.",
		"This point may group several alerts: limit conclusions to the inspected occurrence and say if the remaining occurrences were not assessed.",
		"Explicitly label the result an AI triage suggestion, not a CVSS score or a GitHub severity change. Do not invent a numeric score.",
	],
	fix: [
		"Task: suggest a remediation strategy in at most 70 words.",
		"Give 2 to 4 short bullet points starting with '- '. Name the files or packages to change and how to verify the alert closes.",
		"Describe the approach only. Do not write or paste code.",
	],
	ask: [
		"Task: answer the user's question below in at most 80 words, grounded in this repository.",
	],
	change: [
		"Task: the user below asks you to change the code. Do it for real in this repository.",
		"You may read and edit files and run commands in your dedicated worktree only. Use the session's existing branch. Never commit to the default branch.",
		"Keep the fix minimal and idiomatic, follow the repository instructions, add or update a focused test when practical, and run the relevant build and tests for the touched workspace.",
		"Leave changes uncommitted unless the user asks for a commit. Push only if requested; open a pull request with create_pull_request only if requested.",
	],
};

// Free-form radar questions that ask for an actual change switch the panel to an editing prompt.
// Both code and Git changes must read as requests, not informational questions.
const GIT_INTENT = /\b(branch|branche|commit|push|pr|pull request)\b/i;
const FIX_VERB = /\b(fix|patch|apply|implement|edit|modify|remediate|corrige\w*|répare\w*|modifie\w*|applique\w*|implémente\w*)/i;
const REQUEST = /(^\s*(fix|patch|apply|implement|edit|modify|remediate|corrige|répare|modifie|applique|implémente|go|commit|push|create|open|make|crée|ouvre)\b)|\b(can you|could you|please|go ahead|do it|let'?s|peux[- ]tu|tu peux|pourrais[- ]tu|vas[- ]y|fais|stp|s'il te pla[iî]t)\b/i;
const GIT_ACTION = /^(?:(?:can you|could you|please|go ahead(?: and)?|let'?s|peux[- ]tu|tu peux|pourrais[- ]tu|vas[- ]y|stp)\s+)*(?:(?:commit|push)\b|(?:create|open|make|crée|ouvre)\b.*\b(?:branch|branche|pr|pull request)\b)/i;
const READ_ONLY_QUESTION = /^(?:please\s+)?(?:which|what|where|when|why|how|does|is|are|explain|describe|tell|show|can you (?:explain|describe|tell|show)|could you (?:explain|describe|tell|show)|peux[- ]tu (?:expliquer|décrire|dire|montrer))\b/i;

export function wantsChange(question = "") {
	const text = String(question).trim();
	if (!text) return false;
	if (READ_ONLY_QUESTION.test(text)) return false;
	return REQUEST.test(text) && (FIX_VERB.test(text) || (GIT_INTENT.test(text) && GIT_ACTION.test(text)));
}

function branchSlug(finding) {
	return String(finding.rule || finding.id).split("/").pop().replace(/[^a-z0-9-]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

// Same login the "Assign to Copilot" button uses on an alert page (Copilot Autofix, agentic).
// With agentic Autofix billing on, GitHub only accepts its own app bot; older previews still use the coding agent bot.
export const COPILOT_ASSIGNEE = "github-agentic-autofix[bot]";
export const COPILOT_ASSIGNEE_FALLBACK = "copilot-swe-agent[bot]";

export function isCopilotLogin(login = "") {
	return /^(copilot(-swe-agent)?|github-agentic-autofix)(\[bot\])?$/i.test(String(login));
}

export function radarFindingUrl(finding, repo) {
	return finding.htmlUrl || alertUrl(finding, repo);
}

export function canAssignCopilot(finding) {
	return finding?.source === "code-scanning";
}

/** Picks the alert the radar shows for a finding: same rule and location, else the oldest open one. */
export function pickRadarAlert(alerts = [], finding) {
	const same = alerts.filter((a) => a.rule?.id === finding.rule && a.state !== "dismissed" && a.state !== "fixed");
	const at = same.find(
		(a) => a.most_recent_instance?.location?.path === finding.path && a.most_recent_instance?.location?.start_line === finding.line,
	);
	return at ?? same.sort((a, b) => (a.number ?? 0) - (b.number ?? 0))[0] ?? null;
}

export function assignCopilotRequest(alert, repo, bot = COPILOT_ASSIGNEE) {
	if (!repo) throw new Error("Repository is not resolved.");
	const keep = (alert.assignees ?? []).map((a) => a.login).filter((login) => login && !isCopilotLogin(login));
	return {
		path: `repos/${repo}/code-scanning/alerts/${alert.number}`,
		body: { assignees: [...keep, bot] },
	};
}

export function radarAttachment(finding, cwd) {
	if (!finding.line || !finding.path || !cwd) return null;
	const root = realpathSync(cwd);
	const inside = (path) => {
		const rel = relative(root, path);
		return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
	};
	const candidate = resolve(root, finding.path);
	if (isAbsolute(finding.path) || !inside(candidate)) throw new Error("Alert attachment path must stay inside the repository.");
	let path;
	try {
		path = realpathSync(candidate);
	} catch (error) {
		if (error.code === "ENOENT") return null;
		throw error;
	}
	if (!inside(path)) throw new Error("Alert attachment symlink must stay inside the repository.");
	return {
		type: "file",
		path,
		displayName: `${finding.path.split("/").at(-1)}:${finding.line}`,
		lineRange: { start: Math.max(1, finding.line - 18), end: finding.line + 14 },
	};
}

export function radarPrompt(kind, finding, question = "", { attached = false, repo = null } = {}) {
	const task = RADAR_TASK[kind];
	if (!task) throw new Error(`unknown radar prompt ${kind}`);
	const where = finding.line ? `${finding.path}:${finding.line}` : finding.path;
	const brief = findingBrief(finding);
	const change = kind === "change";
	const assess = kind === "assess";
	const look = assess
		? finding.source === "secret-scanning"
			? "Assess from alert metadata only. Do not call tools or read the affected file. Never look up or display a secret value. Credential validity, permissions and usage are unknown unless supplied."
			: `${attached ? "The flagged lines are attached as a starting point. " : ""}Perform a brief read-only inspection in this repository, using only file-reading and code-search tools, of at most six relevant files. Trace the representative location's callers and access/validation controls; for dependencies inspect manifest/lockfile and usage. Do not run shell commands, tests or the application; do not access networks, delegate to agents or read credentials, .env files or secret values. If evidence is inaccessible or incomplete, say so.`
		: change
		? attached
			? `The flagged lines of ${finding.path} are attached as a starting point. Suggested branch name: security-radar/${branchSlug(finding)}.`
			: `Suggested branch name: security-radar/${branchSlug(finding)}.`
		: attached
			? `The flagged lines of ${finding.path} are attached. Answer from that attachment and this context. Do not call any tools. Do not paste the vulnerable snippet.`
			: finding.source === "secret-scanning"
				? "Answer from alert metadata only. Do not call any tools. Never look up or display a secret value."
				: "Answer from this alert context and what you already know about the repository. Do not call any tools.";
	const lines = [
		`Attack surface radar canvas on ${repoLabel(repo)}.`,
		`Alert: ${finding.title}. Rule ${finding.rule}. Source ${finding.source}. Severity ${finding.severity}. ${finding.count} open alert(s). Location ${where}.`,
		`Context: ${brief.what}`,
		...(change ? [`Remediation intent: ${finding.remediation}`] : []),
		look,
		...task,
	];
	if (kind === "ask" || change) lines.push(`${change ? "Request" : "Question"}: ${String(question).trim().slice(0, 500)}`);
	if (change) {
		lines.push(
			"When done, reply in English in at most 80 words for a small side panel: the branch, the files changed, the tests you ran and their result, and the PR link if you opened one. No headings, no tables, no code blocks.",
			"Never look up or display secret values. Do not include attack strings, payloads, or a proof of concept in code, tests, commits, the PR or the reply.",
		);
	} else {
		lines.push(
			`${assess ? "After the bounded inspection, reply" : "Reply right away"} in English with only the answer text. It is rendered inside a small side panel, so no headings, no tables, no code blocks.`,
			"Do not include attack strings, payloads, secret values, or a proof of concept. Do not edit files.",
		);
	}
	return lines.join("\n");
}

export function radarOfflineAnswer(kind, finding) {
	const brief = findingBrief(finding);
	if (kind === "assess") return "Contextual assessment unavailable: Copilot did not return a usable analysis. No AI priority was assigned. GitHub severity and the radar position are unchanged; retry Assess priority to inspect the repository evidence.";
	if (kind === "fix") return `- ${finding.remediation}\n- Rerun code scanning or Dependabot and confirm the alert closes.`;
	if (kind === "change") {
		return `Copilot did not report back in time. Check the main chat and the current branch for its progress. Fix direction: ${finding.remediation}`;
	}
	if (kind === "ask") {
		return `Live Copilot did not answer in time, so here is the summary from the alert data. ${brief.what} Fix direction: ${finding.remediation}`;
	}
	return [brief.what, brief.where].filter(Boolean).join(" ");
}

export function radarKpis(findings = [], totals = EMPTY_TOTALS) {
	const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
	for (const finding of findings) {
		if (finding.bySeverity) {
			for (const [sev, n] of Object.entries(finding.bySeverity)) bySeverity[sev] = (bySeverity[sev] ?? 0) + n;
		} else {
			bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + finding.count;
		}
	}
	const mapped = Object.values(bySeverity).reduce((sum, count) => sum + count, 0);
	const open = totals.codeScanning + totals.dependabot + totals.secretScanning;
	const bumps = findings.filter((finding) => finding.source === "dependabot" && finding.id !== "dep-rest");
	return {
		open,
		bySeverity,
		mapped,
		criticalHigh: bySeverity.critical + bySeverity.high,
		criticalHighPct: mapped ? Math.round(((bySeverity.critical + bySeverity.high) / mapped) * 100) : 0,
		secrets: totals.secretScanning,
		supplyChainPct: open ? Math.round((totals.dependabot / open) * 100) : 0,
		quickWinBumps: bumps.length,
		quickWinAlerts: bumps.reduce((sum, finding) => sum + finding.count, 0),
	};
}

export function auditBrief(model = complianceModel()) {
	const t = model.totals;
	const lines = [
		`# ${model.repo ?? "Repository"} — NIS2 / DORA posture brief`,
		"",
		DISCLAIMER,
		model.applicability,
		"",
		`Repository: ${model.repo ?? "not resolved"}`,
		`Alert data as of: ${t.asOf ?? "not synced yet"}`,
		`Open code scanning alerts: ${t.codeScanning}`,
		`Open Dependabot alerts: ${t.dependabot}`,
		`Open secret scanning alerts: ${t.secretScanning} (types only, values hidden)`,
		"",
		`Illustrative posture today: ${model.score} / 100`,
		`Once critical and high findings are fixed: ${model.projected} / 100 (+${model.lift})`,
		"",
		"## Control themes",
	];
	for (const control of model.controls) {
		lines.push(`### ${control.title} — ${control.score}/20 (→ ${control.projectedScore}/20)`);
		lines.push(control.framework);
		lines.push(control.summary);
		lines.push(`Open mapped alerts: ${control.alerts}`);
		for (const finding of control.findings) lines.push(`- ${finding.title} · ${finding.severity} · ${finding.count} · ${finding.where} · ${finding.url}`);
		for (const item of control.evidence) {
			const status = item.status === true ? "in place" : item.status === false ? "missing" : "unknown";
			lines.push(`- Evidence: ${item.label} — ${status} (${EVIDENCE_SOURCE_LABEL[item.source] ?? item.source})`);
		}
		lines.push("");
	}
	lines.push("## Summary");
	lines.push(
		"GitHub Advanced Security finds it. Copilot drafts the fix. Push protection stops the next secret before it lands. The alert history is your evidence.",
	);
	lines.push("");
	return lines.join("\n");
}

/** Every user-facing string the model can produce for these findings, for the banned-phrase check. */
export function copyCorpus(findings = [], repo = null) {
	const bits = [DISCLAIMER, auditBrief(complianceModel([], findings, { repo }))];
	for (const finding of findings) {
		const brief = findingBrief(finding);
		bits.push(
			finding.title,
			finding.remediation,
			brief.what,
			brief.where,
			brief.why,
			copilotPromptForFinding(finding, repo),
			explainPromptForFinding(finding, repo),
			...RADAR_ASK_KINDS.map((kind) => radarPrompt(kind, finding, "How bad is this?", { repo })),
			radarOfflineAnswer("explain", finding),
			radarOfflineAnswer("fix", finding),
		);
	}
	return bits.join("\n");
}

export function findBannedPhrase(text = copyCorpus()) {
	const haystack = text.toLowerCase();
	return BANNED.find((phrase) => haystack.includes(phrase.toLowerCase())) ?? null;
}

function repoLabel(repo) {
	return repo || "this repository";
}

function clamp(value, min, max) {
	return Math.max(min, Math.min(max, value));
}

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}
