import assert from "node:assert/strict";
import test from "node:test";

import {
  createDiagnosticLog,
  sanitizeDiagnosticValue,
  selectDiagnosticHeaders,
} from "./diagnostics.mjs";

test("redacts credentials recursively", () => {
  const value = sanitizeDiagnosticValue({
    headers: { Authorization: "Bearer top-secret" },
    privateKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
    response: {
      token: "ghs_example_installation_token",
      deployToken: "ghs_second_installation_token",
      message: "Authorization: Bearer another-secret",
    },
  });

  assert.equal(value.headers.Authorization, "[REDACTED]");
  assert.equal(value.privateKey, "[REDACTED]");
  assert.equal(value.response.token, "[REDACTED]");
  assert.equal(value.response.deployToken, "[REDACTED]");
  assert.doesNotMatch(value.response.message, /another-secret/);
});

test("keeps a bounded cursor-based activity tail", () => {
  let second = 0;
  const log = createDiagnosticLog({
    maxEntries: 2,
    now: () => new Date(Date.UTC(2026, 7, 12, 20, 0, second++)),
  });
  log.add({ operation: "one" });
  log.add({ operation: "two" });
  log.add({ operation: "three" });

  assert.deepEqual(log.snapshot().entries.map((entry) => entry.operation), ["two", "three"]);
  assert.deepEqual(log.snapshot(2).entries.map((entry) => entry.operation), ["three"]);
  const cleared = log.clear();
  assert.equal(cleared.cursor, 3);
  assert.equal(cleared.retained, 0);
});

test("selects only safe diagnostic headers", () => {
  const headers = new Headers({
    Authorization: "Bearer secret",
    Location: "https://api.github.com/status/job",
    "X-GitHub-Request-Id": "ABC1:123",
    "X-OAuth-Scopes": "repo",
  });
  assert.deepEqual(selectDiagnosticHeaders(headers), {
    Location: "https://api.github.com/status/job",
    "X-GitHub-Request-Id": "ABC1:123",
  });
});
