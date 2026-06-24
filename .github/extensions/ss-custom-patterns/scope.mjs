// Scope-path + deep-link helpers and the list/deploy operations against the
// private-preview custom patterns REST API.

import { ghApi } from "./gh.mjs";

// Build the API path for a given level + target.
export function scopePath(level, target) {
    if (level === "enterprise") {
        if (!target.enterprise) throw new Error("Enterprise slug is required.");
        return `/enterprises/${encodeURIComponent(target.enterprise)}/secret-scanning/custom-patterns`;
    }
    if (level === "org") {
        if (!target.org) throw new Error("Organization is required.");
        return `/orgs/${encodeURIComponent(target.org)}/secret-scanning/custom-patterns`;
    }
    if (level === "repo") {
        if (!target.owner || !target.repo) throw new Error("Owner and repo are required.");
        return `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/secret-scanning/custom-patterns`;
    }
    throw new Error(`Unknown level: ${level}`);
}

// Build a UI deep link to a deployed pattern's settings page. Segments are
// encoded to stay consistent with scopePath() (slugs are normally URL-safe, but
// encoding is harmless and avoids surprises).
export function deepLink(level, target, id) {
    if (id == null) return null;
    const eid = encodeURIComponent(String(id));
    if (level === "enterprise") {
        return `https://github.com/enterprises/${encodeURIComponent(target.enterprise)}/settings/advanced_security/custom_patterns/${eid}`;
    }
    if (level === "org") {
        return `https://github.com/organizations/${encodeURIComponent(target.org)}/settings/security_analysis/custom_patterns/${eid}`;
    }
    if (level === "repo") {
        return `https://github.com/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/settings/security_analysis/custom_patterns/${eid}`;
    }
    return null;
}

export async function listDeployed(level, target) {
    const path = scopePath(level, target);
    const res = await ghApi(path);
    if (!res.ok) {
        return {
            ok: false,
            status: res.status,
            error: res.error,
            // 404 here usually means "feature not available for this scope".
            notAvailable: res.status === 404,
        };
    }
    const patterns = Array.isArray(res.data) ? res.data : [];
    return { ok: true, patterns };
}

export async function deployPatterns(level, target, patterns) {
    if (!Array.isArray(patterns) || patterns.length === 0) {
        return { ok: false, error: "No patterns selected to deploy." };
    }
    const path = scopePath(level, target);
    const res = await ghApi(path, { method: "POST", body: { patterns } });
    if (!res.ok) {
        return {
            ok: false,
            status: res.status,
            error: res.error,
            validationErrors: res.data?.validation_errors,
        };
    }
    return { ok: true, created: res.data?.created_patterns || res.data || [] };
}
