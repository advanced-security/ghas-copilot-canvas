import test from "node:test";
import assert from "node:assert/strict";

import {
  API_TOKEN_HEADER,
  authorizeLoopbackApiRequest,
  createLoopbackApiToken,
} from "./loopback-auth.mjs";

const expectedOrigin = "http://127.0.0.1:12345";

test("creates unique loopback API tokens", () => {
  const first = createLoopbackApiToken();
  const second = createLoopbackApiToken();
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first, second);
});

test("requires the per-canvas API token", () => {
  const apiToken = createLoopbackApiToken();
  assert.throws(
    () => authorizeLoopbackApiRequest({}, { apiToken, expectedOrigin }),
    (error) => error.status === 403 && /token/i.test(error.message),
  );
  assert.throws(
    () => authorizeLoopbackApiRequest({ [API_TOKEN_HEADER]: "wrong" }, { apiToken, expectedOrigin }),
    (error) => error.status === 403 && /token/i.test(error.message),
  );
});

test("accepts token-authenticated same-origin and non-browser requests", () => {
  const apiToken = createLoopbackApiToken();
  assert.doesNotThrow(() => authorizeLoopbackApiRequest({
    [API_TOKEN_HEADER]: apiToken,
    origin: expectedOrigin,
  }, { apiToken, expectedOrigin }));
  assert.doesNotThrow(() => authorizeLoopbackApiRequest({
    [API_TOKEN_HEADER]: apiToken,
  }, { apiToken, expectedOrigin }));
});

test("rejects a mismatched browser origin even with the token", () => {
  const apiToken = createLoopbackApiToken();
  assert.throws(
    () => authorizeLoopbackApiRequest({
      [API_TOKEN_HEADER]: apiToken,
      origin: "https://example.com",
    }, { apiToken, expectedOrigin }),
    (error) => error.status === 403 && /origin/i.test(error.message),
  );
});
