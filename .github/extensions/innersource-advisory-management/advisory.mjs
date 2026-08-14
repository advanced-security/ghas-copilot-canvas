export const ECOSYSTEMS = [
  "npm",
  "PyPI",
  "RubyGems",
  "Maven",
  "NuGet",
  "Packagist",
  "Go",
  "crates.io",
  "Hex",
  "Pub",
  "SwiftURL",
  "GitHub Actions",
];

export function createGitHubDocsSampleOsv() {
  return {
    schema_version: "1.4.0",
    id: "EXAMPLE-2024-001",
    modified: "2024-01-15T10:00:00Z",
    summary: "Example vulnerability in example-package",
    details: "A detailed description of the vulnerability.",
    aliases: ["CVE-2024-12345"],
    severity: [{
      type: "CVSS_V3",
      score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }],
    affected: [{
      package: {
        ecosystem: "npm",
        name: "example-package",
      },
      ranges: [{
        type: "ECOSYSTEM",
        events: [
          { introduced: "0" },
          { fixed: "1.2.3" },
        ],
      }],
    }],
    database_specific: {
      severity: "Critical",
    },
    references: [{
      type: "ADVISORY",
      url: "https://example.com/advisory",
    }],
    published: "2024-01-15T10:00:00Z",
  };
}

const GRAPHQL_ECOSYSTEMS = {
  ACTIONS: "GitHub Actions",
  COMPOSER: "Packagist",
  ERLANG: "Hex",
  GO: "Go",
  MAVEN: "Maven",
  NPM: "npm",
  NUGET: "NuGet",
  PIP: "PyPI",
  PUB: "Pub",
  RUBYGEMS: "RubyGems",
  RUST: "crates.io",
  SWIFT: "SwiftURL",
};

const CVSS_V3_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function byteLength(value) {
  return new TextEncoder().encode(String(value ?? "")).length;
}

function titleCase(value) {
  const text = String(value || "").toLowerCase();
  return text ? text[0].toUpperCase() + text.slice(1) : "";
}

export function normalizeScope(scope) {
  const type = scope?.type === "organization" ? "organization" : scope?.type === "enterprise" ? "enterprise" : "";
  const slug = String(scope?.slug || "").trim();
  if (!type) throw new Error("Scope type must be enterprise or organization.");
  if (!slug) throw new Error(`${titleCase(type)} slug is required.`);
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$/.test(slug)) {
    throw new Error(`${titleCase(type)} slug is not valid.`);
  }
  return { type, slug };
}

export function normalizeEcosystem(value) {
  const raw = String(value || "").trim();
  if (GRAPHQL_ECOSYSTEMS[raw.toUpperCase()]) return GRAPHQL_ECOSYSTEMS[raw.toUpperCase()];
  return ECOSYSTEMS.find((item) => item.toLowerCase() === raw.toLowerCase()) || raw;
}

export function vulnerableRangeToAffected(node) {
  const ecosystem = normalizeEcosystem(node?.package?.ecosystem);
  const name = String(node?.package?.name || "").trim();
  const rawRange = String(node?.vulnerableVersionRange || "").trim();
  const firstPatched = String(node?.firstPatchedVersion?.identifier || "").trim();
  const affected = { package: { ecosystem, name } };

  const exact = rawRange.match(/^=\s*(.+)$/);
  if (exact) {
    affected.versions = [exact[1].trim()];
    return affected;
  }

  const events = [];
  let introduced = "";
  let upperKind = "";
  let upperVersion = "";
  for (const part of rawRange.split(",").map((item) => item.trim()).filter(Boolean)) {
    let match = part.match(/^>=\s*(.+)$/);
    if (match) {
      introduced = match[1].trim();
      continue;
    }
    match = part.match(/^>\s*(.+)$/);
    if (match) {
      introduced = match[1].trim();
      continue;
    }
    match = part.match(/^<=\s*(.+)$/);
    if (match) {
      upperKind = "last_affected";
      upperVersion = match[1].trim();
      continue;
    }
    match = part.match(/^<\s*(.+)$/);
    if (match) {
      upperKind = "fixed";
      upperVersion = match[1].trim();
    }
  }

  if (!introduced && (upperVersion || firstPatched)) introduced = "0";
  if (introduced) events.push({ introduced });
  if (firstPatched) {
    events.push({ fixed: firstPatched });
  } else if (upperKind && upperVersion) {
    events.push({ [upperKind]: upperVersion });
  }

  if (events.length) {
    affected.ranges = [{ type: "ECOSYSTEM", events }];
  } else if (rawRange) {
    affected.versions = [rawRange.replace(/^=\s*/, "")];
  }
  return affected;
}

function advisorySeverityEntries(advisory) {
  const severities = advisory?.cvssSeverities || {};
  const entries = [];
  const v3 = severities.cvssV3?.vectorString;
  const v4 = severities.cvssV4?.vectorString;
  if (v3) entries.push({ type: "CVSS_V3", score: v3 });
  if (v4) entries.push({ type: "CVSS_V4", score: v4 });
  return entries;
}

function buildOsv(advisory) {
  const osv = {
    schema_version: "1.4.0",
    id: advisory.ghsaId,
    modified: advisory.updatedAt,
    summary: advisory.summary || advisory.ghsaId,
    details: advisory.description || advisory.summary || advisory.ghsaId,
    severity: advisorySeverityEntries(advisory),
    affected: [],
  };

  const aliases = (advisory.identifiers || [])
    .map((identifier) => identifier?.value)
    .filter((value) => /^CVE-\d{4}-\d+$/i.test(String(value || "")));
  if (aliases.length) osv.aliases = [...new Set(aliases)];
  if (advisory.publishedAt) osv.published = advisory.publishedAt;
  if (advisory.withdrawnAt) osv.withdrawn = advisory.withdrawnAt;
  if (advisory.severity) osv.database_specific = { severity: titleCase(advisory.severity) };

  const references = (advisory.references || [])
    .map((reference) => reference?.url)
    .filter(Boolean)
    .map((url) => ({ type: "WEB", url }));
  if (references.length) osv.references = references;
  return osv;
}

export function graphqlNodesToAdvisories(nodes, scope) {
  const grouped = new Map();
  for (const node of Array.isArray(nodes) ? nodes : []) {
    const advisory = node?.advisory;
    if (!advisory?.ghsaId) continue;
    let item = grouped.get(advisory.ghsaId);
    if (!item) {
      const reportedSeverities = [node.severity, advisory.severity]
        .map((value) => String(value || "").toLowerCase())
        .filter((value) => value && value !== "unknown");
      const cvssScore = [
        advisory.cvssSeverities?.cvssV4,
        advisory.cvssSeverities?.cvssV3,
      ].find((cvss) => cvss?.vectorString)?.score;
      const severity = reportedSeverities[0] || severityForScore(cvssScore);
      const osv = buildOsv(advisory);
      if (severity && !["unknown", "none"].includes(severity)) {
        osv.database_specific = { severity: titleCase(severity) };
      }
      item = {
        ghsaId: advisory.ghsaId,
        summary: advisory.summary || advisory.ghsaId,
        severity,
        permalink: advisory.permalink || null,
        withdrawn: Boolean(advisory.withdrawnAt),
        updatedAt: advisory.updatedAt || node.updatedAt || null,
        sourceScope: normalizeScope(scope),
        sourceRanges: [],
        osv,
      };
      grouped.set(advisory.ghsaId, item);
    }

    const affected = vulnerableRangeToAffected(node);
    const key = JSON.stringify(affected);
    if (!item.osv.affected.some((entry) => JSON.stringify(entry) === key)) {
      item.osv.affected.push(affected);
    }
    item.sourceRanges.push({
      ecosystem: affected.package.ecosystem,
      package: affected.package.name,
      range: node.vulnerableVersionRange,
      firstPatchedVersion: node.firstPatchedVersion?.identifier || null,
    });
  }

  return [...grouped.values()].sort((left, right) => {
    const time = String(right.updatedAt || "").localeCompare(String(left.updatedAt || ""));
    return time || left.ghsaId.localeCompare(right.ghsaId);
  });
}

export function validateOsv(advisory) {
  const errors = [];
  const warnings = [];
  if (!isObject(advisory)) {
    return { valid: false, errors: ["Advisory must be a JSON object."], warnings };
  }

  const id = String(advisory.id || "").trim();
  if (!id) errors.push("id is required.");
  if (id.length > 2048) errors.push("id must not exceed 2,048 characters.");

  const schemaVersion = String(advisory.schema_version || "");
  if (schemaVersion && !/^1\.\d+\.\d+$/.test(schemaVersion)) {
    errors.push("schema_version must be compatible with OSV 1.x (recommended: 1.4.0).");
  }
  if (!String(advisory.modified || "").trim() || Number.isNaN(Date.parse(advisory.modified))) {
    errors.push("modified must be a valid date-time.");
  }

  if (byteLength(advisory.summary) > 1024) errors.push("summary must not exceed 1,024 bytes.");
  if (!String(advisory.summary || "").trim()) warnings.push("summary is blank; GitHub will use id.");
  if (!String(advisory.details || "").trim()) warnings.push("details is blank; GitHub will use summary or id.");

  const severities = Array.isArray(advisory.severity) ? advisory.severity : [];
  const supportedSeverities = severities.filter((entry) =>
    ["CVSS_V3", "CVSS_V4"].includes(entry?.type) && String(entry?.score || "").trim()
  );
  if (!supportedSeverities.length) {
    errors.push("severity must contain a CVSS_V3 or CVSS_V4 vector.");
  }
  for (const entry of severities) {
    if (!["CVSS_V3", "CVSS_V4"].includes(entry?.type)) {
      errors.push(`Unsupported severity type: ${entry?.type || "(blank)"}.`);
    }
    const score = String(entry?.score || "");
    if (entry?.type === "CVSS_V3" && !/^CVSS:3\.[01]\//.test(score)) {
      errors.push("CVSS_V3 score must be a CVSS 3.0 or 3.1 vector.");
    }
    if (entry?.type === "CVSS_V4" && !/^CVSS:4\.0\//.test(score)) {
      errors.push("CVSS_V4 score must be a CVSS 4.0 vector.");
    }
    if (String(entry?.score || "").length > 255) errors.push(`${entry?.type || "severity"} score is too long.`);
  }

  const affected = Array.isArray(advisory.affected) ? advisory.affected : [];
  if (!affected.length) errors.push("At least one affected package is required.");
  affected.forEach((entry, affectedIndex) => {
    const prefix = `affected[${affectedIndex}]`;
    const ecosystem = normalizeEcosystem(entry?.package?.ecosystem);
    const name = String(entry?.package?.name || "").trim();
    if (!ECOSYSTEMS.includes(ecosystem)) errors.push(`${prefix}.package.ecosystem is unsupported.`);
    if (!name) errors.push(`${prefix}.package.name is required.`);
    if (name.length > 255) errors.push(`${prefix}.package.name must not exceed 255 characters.`);

    const ranges = Array.isArray(entry?.ranges) ? entry.ranges : [];
    const versions = Array.isArray(entry?.versions) ? entry.versions.filter(Boolean) : [];
    if (!ranges.length && !versions.length) errors.push(`${prefix} requires ranges or versions.`);
    ranges.forEach((range, rangeIndex) => {
      const rangePrefix = `${prefix}.ranges[${rangeIndex}]`;
      if (!["ECOSYSTEM", "SEMVER"].includes(range?.type)) {
        errors.push(`${rangePrefix}.type must be ECOSYSTEM or SEMVER.`);
      }
      const events = Array.isArray(range?.events) ? range.events : [];
      if (!events.length) errors.push(`${rangePrefix}.events is required.`);
      const fixed = events.filter((event) => event?.fixed != null);
      const lastAffected = events.filter((event) => event?.last_affected != null);
      if (fixed.length && lastAffected.length) {
        errors.push(`${rangePrefix} cannot contain both fixed and last_affected.`);
      }
      if (range?.type === "ECOSYSTEM") {
        if (events.filter((event) => event?.introduced != null).length > 1) {
          errors.push(`${rangePrefix} supports only one introduced event.`);
        }
        if (fixed.length > 1 || lastAffected.length > 1) {
          errors.push(`${rangePrefix} supports only one upper-bound event.`);
        }
      }
      for (const event of events) {
        if (String(event?.fixed || "").length > 50) {
          errors.push(`${rangePrefix}.fixed must not exceed 50 characters.`);
        }
      }
    });
  });

  const aliases = Array.isArray(advisory.aliases) ? advisory.aliases : [];
  if (aliases.some((alias) => String(alias || "").length > 20)) {
    errors.push("CVE aliases must not exceed 20 characters.");
  }
  const ignoredAliases = aliases.filter((alias) => !/^CVE-\d{4}-\d+$/i.test(String(alias || "")));
  if (ignoredAliases.length) warnings.push("Only CVE aliases are preserved by GitHub; other aliases are ignored.");

  if (affected.length > 100) warnings.push("This advisory has more than 100 affected entries; review payload size carefully.");
  return { valid: errors.length === 0, errors, warnings };
}

export function parseCvssV3Vector(vector) {
  const text = String(vector || "").trim();
  if (!/^CVSS:3\.[01]\//.test(text)) return null;
  const metrics = {};
  for (const component of text.split("/").slice(1)) {
    const [key, value] = component.split(":", 2);
    if (key && value) metrics[key] = value;
  }
  return metrics;
}

export function cvssV3Vector(metrics) {
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  if (!required.every((key) => metrics?.[key])) return "";
  return `CVSS:3.1/${required.map((key) => `${key}:${metrics[key]}`).join("/")}`;
}

function roundUpOneDecimal(value) {
  return Math.ceil((value - 1e-10) * 10) / 10;
}

export function cvssV3BaseScore(metrics) {
  if (!metrics) return null;
  const av = CVSS_V3_WEIGHTS.AV[metrics.AV];
  const ac = CVSS_V3_WEIGHTS.AC[metrics.AC];
  const ui = CVSS_V3_WEIGHTS.UI[metrics.UI];
  const c = CVSS_V3_WEIGHTS.CIA[metrics.C];
  const i = CVSS_V3_WEIGHTS.CIA[metrics.I];
  const a = CVSS_V3_WEIGHTS.CIA[metrics.A];
  const changed = metrics.S === "C";
  const prWeights = changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const pr = prWeights[metrics.PR];
  if ([av, ac, ui, c, i, a, pr].some((value) => value == null)) return null;

  const impactBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15)
    : 6.42 * impactBase;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = changed
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUpOneDecimal(raw);
}

export function severityForScore(score) {
  if (score == null || Number.isNaN(Number(score))) return "unknown";
  const value = Number(score);
  if (value === 0) return "none";
  if (value < 4) return "low";
  if (value < 7) return "moderate";
  if (value < 9) return "high";
  return "critical";
}
