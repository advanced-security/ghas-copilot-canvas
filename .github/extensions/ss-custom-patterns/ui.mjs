import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const dir = path.dirname(fileURLToPath(import.meta.url));

// Read fresh each call so edits show up after an extensions reload.
export function renderHtml() {
    return readFileSync(path.join(dir, "index.html"), "utf8");
}
