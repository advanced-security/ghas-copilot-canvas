// In-memory, redacted API activity log shared by the canvas's HTTP server.
// Bounded to a fixed number of entries; nothing is persisted to disk.

const DEFAULT_MAX_ENTRIES = 100;
const DEFAULT_MAX_SECTION_BYTES = 32 * 1024;
const MAX_DEPTH = 12;
const MAX_ARRAY_ITEMS = 200;
const MAX_STRING_LENGTH = 16 * 1024;

const SENSITIVE_KEY = /authorization|private.?key|client.?secret|access.?token|(^|[_-])token($|[_-])|token$|password|jwt|pem|cookie/i;
const PRIVATE_KEY_PATTERN = /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g;
const GITHUB_TOKEN_PATTERN = /\b(?:github_pat_|gh[opsur]_)[A-Za-z0-9_]{16,}\b/g;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]+\b/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

function redactString(value) {
  return String(value)
    .replace(PRIVATE_KEY_PATTERN, "[REDACTED PRIVATE KEY]")
    .replace(GITHUB_TOKEN_PATTERN, "[REDACTED GITHUB TOKEN]")
    .replace(BEARER_PATTERN, "******")
    .replace(JWT_PATTERN, "[REDACTED JWT]");
}

export function sanitizeDiagnosticValue(value, key = "", seen = new WeakSet(), depth = 0) {
  if (SENSITIVE_KEY.test(key)) return "[REDACTED]";
  if (value == null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") {
    const redacted = redactString(value);
    return redacted.length > MAX_STRING_LENGTH
      ? `${redacted.slice(0, MAX_STRING_LENGTH)}\n...[truncated ${redacted.length - MAX_STRING_LENGTH} characters]`
      : redacted;
  }
  if (typeof value !== "object") return String(value);
  if (depth >= MAX_DEPTH) return "[MAX DEPTH]";
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);

  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeDiagnosticValue(item, "", seen, depth + 1));
    if (value.length > MAX_ARRAY_ITEMS) {
      items.push(`[...${value.length - MAX_ARRAY_ITEMS} more items]`);
    }
    return items;
  }

  return Object.fromEntries(Object.entries(value).map(([entryKey, entryValue]) => [
    entryKey,
    sanitizeDiagnosticValue(entryValue, entryKey, seen, depth + 1),
  ]));
}

function boundedSection(value, maxBytes) {
  const sanitized = sanitizeDiagnosticValue(value);
  const serialized = JSON.stringify(sanitized);
  const bytes = Buffer.byteLength(serialized);
  if (bytes <= maxBytes) return sanitized;
  return {
    truncated: true,
    originalBytes: bytes,
    preview: serialized.slice(0, maxBytes),
  };
}

export function createDiagnosticLog(options = {}) {
  const maxEntries = options.maxEntries || DEFAULT_MAX_ENTRIES;
  const maxSectionBytes = options.maxSectionBytes || DEFAULT_MAX_SECTION_BYTES;
  const now = options.now || (() => new Date());
  const entries = [];
  let sequence = 0;

  function add(input = {}) {
    const entry = {
      id: ++sequence,
      timestamp: input.timestamp || now().toISOString(),
      level: input.level || "info",
      source: input.source || "canvas",
      operation: input.operation || "Activity",
    };
    if (input.durationMs != null) entry.durationMs = input.durationMs;
    if (input.message) entry.message = sanitizeDiagnosticValue(input.message);
    if (input.request !== undefined) entry.request = boundedSection(input.request, maxSectionBytes);
    if (input.response !== undefined) entry.response = boundedSection(input.response, maxSectionBytes);
    if (input.error !== undefined) entry.error = boundedSection(input.error, maxSectionBytes);
    entries.push(entry);
    if (entries.length > maxEntries) entries.splice(0, entries.length - maxEntries);
    return entry;
  }

  function snapshot(after = 0) {
    const cursor = Number.isFinite(Number(after)) ? Number(after) : 0;
    return {
      entries: entries.filter((entry) => entry.id > cursor),
      cursor: sequence,
      retained: entries.length,
      maxEntries,
    };
  }

  function clear() {
    entries.splice(0, entries.length);
    return snapshot(sequence);
  }

  return { add, clear, snapshot };
}
