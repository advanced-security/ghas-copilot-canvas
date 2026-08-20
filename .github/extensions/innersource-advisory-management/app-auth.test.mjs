import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";

import {
  createGitHubAppJwt,
  generateInstallationAccessToken,
  selectInstallation,
} from "./app-auth.mjs";

function testKeyPair() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: pair.publicKey,
  };
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("creates a ten-minute RS256 GitHub App JWT", () => {
  const { privateKey, publicKey } = testKeyPair();
  const jwt = createGitHubAppJwt("Iv23liExample", privateKey, Date.UTC(2026, 7, 12, 20, 0, 0));
  const [header, payload, signature] = jwt.split(".");

  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "RS256", typ: "JWT" });
  const claims = JSON.parse(Buffer.from(payload, "base64url"));
  assert.equal(claims.iss, "Iv23liExample");
  assert.equal(claims.exp - claims.iat, 600);
  assert.equal(
    verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url")),
    true,
  );
});

test("selects an enterprise installation and requires write access", () => {
  const installation = {
    id: 42,
    target_type: "Enterprise",
    account: { slug: "avocado-corp" },
    permissions: { enterprise_innersource_vulnerabilities: "write" },
  };
  assert.equal(
    selectInstallation([installation], { type: "enterprise", slug: "avocado-corp" }).id,
    42,
  );
  assert.throws(
    () => selectInstallation(
      [{ ...installation, permissions: { enterprise_innersource_vulnerabilities: "read" } }],
      { type: "enterprise", slug: "avocado-corp" },
    ),
    /lacks enterprise_innersource_vulnerabilities:write/,
  );
});

test("discovers an installation and generates an access token", async () => {
  const { privateKey } = testKeyPair();
  const requests = [];
  const installation = {
    id: 42,
    app_slug: "advisory-manager",
    target_type: "Enterprise",
    account: { slug: "avocado-corp" },
    permissions: { enterprise_innersource_vulnerabilities: "write" },
  };
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (url.includes("/app/installations?")) return response([installation]);
    if (url.endsWith("/app/installations/42/access_tokens")) {
      return response({ token: "ghs_test_installation_token", expires_at: "2026-08-12T21:00:00Z" }, 201);
    }
    return response({ message: "Not found" }, 404);
  };

  const result = await generateInstallationAccessToken(
    { type: "enterprise", slug: "avocado-corp" },
    {
      appIdentifier: "12345",
      privateKey,
      fetchImpl,
      now: Date.UTC(2026, 7, 12, 20, 0, 0),
    },
  );

  assert.equal(result.token, "ghs_test_installation_token");
  assert.equal(result.installationId, "42");
  assert.equal(result.scope.slug, "avocado-corp");
  assert.deepEqual(result.permissions, { enterprise_innersource_vulnerabilities: "write" });
  assert.equal(requests.length, 2);
  assert.match(requests[0].options.headers.Authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  assert.equal(requests[1].options.method, "POST");
});
