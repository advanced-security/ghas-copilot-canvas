// Scope-path + deep-link helpers and the list/deploy operations against the
// (now GA) custom patterns REST API.

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

// The GA list endpoints paginate (default 30/page, max 100), unlike the old
// private-preview API this canvas was originally built against. Walk every
// page so orgs/enterprises/repos with more than one page of deployed
// patterns don't silently show an incomplete "deployed" state.
const LIST_PER_PAGE = 100;
const MAX_LIST_PAGES = 200; // safety cap: 20,000 patterns

export async function listDeployed(level, target) {
    const path = scopePath(level, target);
    const patterns = [];
    let page = 1;
    while (page <= MAX_LIST_PAGES) {
        const res = await ghApi(`${path}?per_page=${LIST_PER_PAGE}&page=${page}`);
        if (!res.ok) {
            // First page failing means the scope/feature itself is unavailable
            // (or errored); nothing to show. A later page failing (e.g. a
            // transient error mid-pagination) still leaves earlier pages
            // usable, so surface what we have plus a warning instead of
            // discarding it.
            if (page === 1) {
                return {
                    ok: false,
                    status: res.status,
                    error: res.error,
                    // 404 here usually means "feature not available for this scope".
                    notAvailable: res.status === 404,
                };
            }
            return { ok: true, patterns, warning: `Stopped after page ${page - 1}: ${res.error || "request failed"}` };
        }
        const batch = Array.isArray(res.data) ? res.data : [];
        patterns.push(...batch);
        if (batch.length < LIST_PER_PAGE) break; // last page
        page += 1;
    }
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
