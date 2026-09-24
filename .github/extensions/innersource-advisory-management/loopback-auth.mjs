import { randomBytes, timingSafeEqual } from "node:crypto";

export const API_TOKEN_HEADER = "x-canvas-api-token";

function forbidden(message) {
  const error = new Error(message);
  error.status = 403;
  return error;
}

function tokensMatch(actual, expected) {
  const actualBytes = Buffer.from(String(actual || ""));
  const expectedBytes = Buffer.from(String(expected || ""));
  return actualBytes.length === expectedBytes.length
    && timingSafeEqual(actualBytes, expectedBytes);
}

export function createLoopbackApiToken() {
  return randomBytes(32).toString("base64url");
}

export function authorizeLoopbackApiRequest(headers, { apiToken, expectedOrigin }) {
  if (!tokensMatch(headers?.[API_TOKEN_HEADER], apiToken)) {
    throw forbidden("Canvas API token is missing or invalid.");
  }

  const origin = String(headers?.origin || "");
  if (origin && origin !== expectedOrigin) {
    throw forbidden("Cross-origin API requests are not allowed.");
  }
}
