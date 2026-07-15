# 🔐 Secret Scanning Custom Pattern Deployment

> `.github/extensions/ghsp-custom-pattern-deployment/`

A GitHub Copilot CLI **canvas extension** for bulk-deploying secret-scanning custom patterns. It loads `patterns.yml` configs (for example the samples in [advanced-security/secret-scanning-custom-patterns](https://github.com/advanced-security/secret-scanning-custom-patterns)) and deploys the patterns you pick to an **enterprise, organization, or repository** in one action, using the private-preview custom-patterns REST API.

It exists because deploying these patterns through the GitHub UI one at a time is slow and error-prone. This canvas turns that into a browse, filter, select, deploy flow.

---

## Features

- **Load `patterns.yml` from anywhere** — recursively scans a repo for every `patterns.yml` (default `advanced-security/secret-scanning-custom-patterns`) or reads from a local path, with an optional branch/ref override.
- **Expandable tree, grouped by config file** — expand any pattern to see its type, regex, start/end delimiters, additional "must not match" rules, and `test:` cases with the start/end offset substring highlighted inline.
- **Three deploy levels** — Enterprise (slug), Organization, or Repository, each with the correct API path and UI deep links.
- **Load deployed state** — queries what already exists at the target and shows live **State** (published/unpublished) and **Push Protection** (on/off) per pattern, with deep links to the exact settings page to manage each.
- **Bulk deploy** — select across files and create many patterns at once, with a confirmation modal that warns they land **unpublished**.
- **Smart filtering and selection** — filter by name, State, Push Protection, and "not deployed"; filter-aware Select all / Deselect all; a "skip already-deployed" toggle; and warnings when a filter hides patterns you have selected.
- **In-UI limitations panel** — surfaces the private-preview API constraints right where you are working.

---

## Where this extension goes the extra mile

- **Works at scale.** The repository picker queries the GitHub **Search API server-side** instead of paginating through everything; an org with 5k+ repos resolves in seconds rather than minutes. Both org and repo pickers **auto-switch** between a native dropdown (under 100 entries) and a debounced type-ahead (100+), with stale-response guards so fast typing never renders the wrong list.
- **Understands the full lifecycle: unpublished -> dry run -> publish -> push protection.** Patterns are always created unpublished, and publishing plus enabling push protection are UI-only today. Rather than pretend the API can do those steps, the badges deep-link to the exact place to finish the flow, at every level (enterprise / org / repo).
- **Per-level deep-link correctness.** Open links and push-protection config links differ by level (repo uses the per-pattern page; org/enterprise use `pattern_configurations` filtered by name), and the exact URL formats were verified against a live enterprise.
- **Honest status modeling.** Unpublished patterns are not linked, because they do not exist on the config page yet. Push-protection-off badges are color-coded (actionable vs not). And because there is **no API signal** for "dry run complete / ready to publish," the UI does not invent one.
- **Auth that just works.** It shells out to `gh` so it inherits your existing login, and transparently retries with environment tokens stripped when a scoped `GH_TOKEN` lacks `admin:org` / `admin:enterprise`.
- **Resilient by design.** The frontend `api()` helper always resolves to a consistent `{ ok, error }` shape, so a mid-call server restart never leaves a button stuck; YAML parsing is fault-isolated per file so one bad config does not sink the whole load; and remote fetching uses limited concurrency to stay gentle on the API.
- **Zero external dependencies.** `js-yaml` is vendored, the UI is served from a loopback HTTP server, and there is no `node_modules` to install.

---

## Usage

Ask Copilot to open the canvas:

```
Open the secret scanning custom pattern deployment canvas
```

Then in the canvas:

1. **Load patterns** — accept the default source repo or point it at a local path, and click **Load patterns.yml**.
2. **Pick a target** — choose Enterprise, Org, or Repo and select the destination.
3. **Load deployed state** — see which patterns already exist and their State / Push Protection status.
4. **Select and deploy** — check the patterns you want and click **Deploy selected**. They are created as **unpublished**.

---

## Known limitations (private-preview API)

These are constraints of the underlying API, not the extension. The canvas surfaces them in its limitations panel:

- Patterns are created **unpublished**. Publishing and enabling push protection must be done in the GitHub UI.
- **No API signal for dry-run status** — you cannot tell when a pattern's dry run has completed or that it is ready to publish.
- **No update or delete** of existing patterns via the API.
- List endpoints have **no server-side filtering, sorting, or pagination** (filtering in the canvas is client-side).
- Enterprise endpoints are **GHEC only** and do not support GitHub App authentication.

---

## Files

| File | Purpose |
|---|---|
| `extension.mjs` | Canvas registration + loopback HTTP server and API endpoints |
| `gh.mjs` | `gh api` wrapper (auth fallback, pagination, raw file fetch) |
| `patterns.mjs` | Remote/local discovery and normalization of `patterns.yml` |
| `scope.mjs` | Scope-path helpers, deep-link generation, list/deploy operations |
| `ui.mjs` | HTML renderer for the canvas iframe |
| `index.html` | UI layout and styling |
| `app.js` | Frontend logic: loading, rendering, filtering, selection, deploy |
| `js-yaml.mjs` | Vendored YAML parser (no external dependency) |
