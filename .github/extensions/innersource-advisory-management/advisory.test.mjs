import test from "node:test";
import assert from "node:assert/strict";

import {
  createGitHubDocsSampleOsv,
  cvssV3BaseScore,
  graphqlNodesToAdvisories,
  normalizeScope,
  parseCvssV3Vector,
  validateOsv,
  vulnerableRangeToAffected,
} from "./advisory.mjs";

const minimalAdvisory = {
  schema_version: "1.4.0",
  id: "INTERNAL-2026-001",
  modified: "2026-08-12T12:00:00Z",
  summary: "Example vulnerability",
  details: "Example details",
  severity: [{
    type: "CVSS_V3",
    score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  }],
  affected: [{
    package: { ecosystem: "npm", name: "example-package" },
    ranges: [{
      type: "ECOSYSTEM",
      events: [{ introduced: "0" }, { fixed: "1.2.3" }],
    }],
  }],
};

test("validates a minimal GitHub OSV advisory", () => {
  const result = validateOsv(minimalAdvisory);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("reports invalid scopes as client errors", () => {
  assert.throws(
    () => normalizeScope({ type: "organization", slug: "" }),
    (error) => error.status === 422 && /slug is required/i.test(error.message),
  );
  assert.throws(
    () => normalizeScope({ type: "repository", slug: "octo-repo" }),
    (error) => error.status === 422 && /scope type/i.test(error.message),
  );
});

test("provides the exact GitHub Docs OSV sample", () => {
  const sample = createGitHubDocsSampleOsv();
  assert.deepEqual(sample, {
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
  });
  assert.equal(validateOsv(sample).valid, true);
});

test("rejects unsupported Git ranges and missing CVSS", () => {
  const advisory = structuredClone(minimalAdvisory);
  advisory.severity = [];
  advisory.affected[0].ranges[0].type = "GIT";
  const result = validateOsv(advisory);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(" "), /CVSS_V3 or CVSS_V4/);
  assert.match(result.errors.join(" "), /ECOSYSTEM or SEMVER/);
});

test("calculates the CVSS 3.1 critical example", () => {
  const metrics = parseCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(cvssV3BaseScore(metrics), 9.8);
});

test("converts GraphQL version ranges to OSV events", () => {
  assert.deepEqual(vulnerableRangeToAffected({
    package: { ecosystem: "NPM", name: "example-package" },
    vulnerableVersionRange: ">= 1.0.0, < 2.0.0",
    firstPatchedVersion: { identifier: "2.0.0" },
  }), {
    package: { ecosystem: "npm", name: "example-package" },
    ranges: [{
      type: "ECOSYSTEM",
      events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
    }],
  });
});

test("groups GraphQL vulnerability ranges into one advisory", () => {
  const advisory = {
    ghsaId: "GHIS-abcd-efgh-ijkl",
    summary: "Example vulnerability",
    description: "Example details",
    severity: "UNKNOWN",
    publishedAt: "2026-08-01T00:00:00Z",
    updatedAt: "2026-08-12T00:00:00Z",
    withdrawnAt: null,
    permalink: "https://github.com/advisories/GHIS-abcd-efgh-ijkl",
    identifiers: [],
    references: [],
    cvssSeverities: {
      cvssV3: { vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
      cvssV4: { vectorString: null, score: null },
    },
  };
  const nodes = [
    {
      advisory,
      severity: "CRITICAL",
      package: { ecosystem: "NPM", name: "example-package" },
      vulnerableVersionRange: "< 1.2.3",
      firstPatchedVersion: { identifier: "1.2.3" },
    },
    {
      advisory,
      severity: "CRITICAL",
      package: { ecosystem: "NPM", name: "example-package" },
      vulnerableVersionRange: ">= 2.0.0, < 2.1.0",
      firstPatchedVersion: { identifier: "2.1.0" },
    },
  ];
  const result = graphqlNodesToAdvisories(nodes, { type: "organization", slug: "octo-org" });
  assert.equal(result.length, 1);
  assert.equal(result[0].severity, "critical");
  assert.equal(result[0].osv.affected.length, 2);
  assert.equal(validateOsv(result[0].osv).valid, true);
});
