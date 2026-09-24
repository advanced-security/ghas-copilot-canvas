import assert from "node:assert/strict";
import test from "node:test";

import {
  parseIncludedResponse,
  parseOauthScopes,
} from "./github.mjs";

test("parses status, headers, and JSON body from gh api --include", () => {
  const response = parseIncludedResponse([
    "HTTP/2.0 202 Accepted",
    "Content-Type: application/json; charset=utf-8",
    "Location: https://api.github.com/status/job",
    "X-GitHub-Request-Id: ABC1:123",
    "",
    '{"id":"job","status":"queued"}',
  ].join("\r\n"));

  assert.equal(response.status, 202);
  assert.equal(response.headers.location, "https://api.github.com/status/job");
  assert.equal(response.headers["x-github-request-id"], "ABC1:123");
  assert.deepEqual(JSON.parse(response.bodyText), { id: "job", status: "queued" });
});

test("leaves body-only gh output unchanged", () => {
  assert.deepEqual(parseIncludedResponse('{"ok":true}'), {
    status: null,
    headers: {},
    bodyText: '{"ok":true}',
  });
});

test("normalizes OAuth scope headers", () => {
  assert.deepEqual(
    parseOauthScopes(" repo, read:enterprise, gist,repo "),
    ["gist", "read:enterprise", "repo"],
  );
});
