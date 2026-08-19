# GHAS Copilot Canvas Extensions

A collection of **GitHub Copilot CLI canvas extensions** for GitHub Advanced Security (GHAS) workflows. Canvases are interactive side-panel UIs that appear inside the Copilot CLI app — they let you interact with rich forms and live data without leaving your terminal workflow.

---

## Extensions

### 1. 🔍 CodeQL Config Builder

> `.github/extensions/codeql-config-builder/`

A form-driven builder for **CodeQL configuration YAML files** (`.github/codeql/codeql-config.yml`). Every field documented at [gh.io/codeql-config](https://gh.io/codeql-config) is supported.

#### What you can build

| Field | Details |
| --- | --- |
| `name` | Free-text name for the config |
| `disable-default-queries` | Toggle the built-in query suite |
| `threat-models` | Dropdown: `remote` / `local` |
| `queries` | List of `uses` entries with optional `name`; autocomplete for standard suites |
| `packs` | Per-language packs with a language picker (all 10 official CodeQL languages) |
| `paths` / `paths-ignore` | Inclusion/exclusion path lists |
| `query-filters` | `include` / `exclude` rules with smart key→value autocomplete |

#### Actions

| Action | Required input | Description |
| --- | --- | --- |
| `load_config` | `owner`, `repo` | Fetch the existing config from a repo |
| `write_codeql_config` | `owner`, `repo`, `yamlContent` | Commit the YAML to the repo |

Both actions accept optional `branch` and `path` parameters.

#### Usage

Ask Copilot to open the canvas:

```text
Open the CodeQL Config Builder for owner/my-repo
```

Or trigger it directly for a specific repo:

```text
Build a CodeQL config for github/my-project and commit it
```

The canvas lets you:

- **Preview YAML** — live render as you fill the form
- **Download YAML** — save `codeql-config.yml` locally
- **Load existing** — pull the current file from GitHub before editing
- **Commit to repo** — push the file via the GitHub API (handles create and update)

---

### 2. 📦 SBOM Dependency Audit

> `.github/extensions/sbom-dependency-audit/`

Scans all repositories in a **GitHub organization** for a given dependency using the [Dependency Graph SBOM API](https://docs.github.com/en/rest/dependency-graph/sboms). Results show version, direct/transitive status, and the full dependency path.

#### Actions

| Action     | Input               | Description                                           |
|------------|---------------------|-------------------------------------------------------|
| `run_scan` | `org`, `dependency` | Scan all repos in an org and return a Markdown report |

Both `org` and `dependency` are also accepted as canvas open inputs to pre-fill the form.

#### Usage

Ask Copilot to open the canvas:

```text
Audit adrienpessu-octodemo for @antv/data-set
```

Or start a scan via agent action:

```text
Run an SBOM scan on my-org for lodash
```

The canvas displays a live table of every repository that contains the dependency, along with:

- **Version** found
- **Direct or transitive** classification
- **Dependency path** from root to the package

<img width="2876" height="1434" alt="image" src="https://github.com/user-attachments/assets/e7d64e14-ec38-4e31-81cd-045294d8e1a0" />

---

### 3. 🔐 Secret Scanning Custom Pattern Deployment

> `.github/extensions/ghsp-custom-pattern-deployment/`

Bulk-deploys **secret-scanning custom patterns** to an **enterprise, organization, or repository**. It loads `patterns.yml` configs (for example the samples in [advanced-security/secret-scanning-custom-patterns](https://github.com/advanced-security/secret-scanning-custom-patterns), or a local path) and turns the slow, one-at-a-time UI workflow into a browse, filter, select, deploy flow over the custom-patterns REST API (GA).

#### Highlights

- **Load from anywhere** — recursive scan of a repo for every `patterns.yml`, or a local path, with branch/ref override.
- **Browse + inspect** — expandable tree grouped by config file, showing type, regex, delimiters, "must not match" rules, and `test:` cases with the offset substring highlighted.
- **Deploy at three levels** — Enterprise / Org / Repo, with per-level API paths and UI deep links.
- **Load deployed state** — live **State** (published/unpublished) and **Push Protection** status per pattern, deep-linked to the right settings page.
- **Bulk deploy** — select across files and create many patterns at once (created as unpublished, per the API).
- **Built for scale** — server-side repo search (5k+ repo orgs resolve in seconds) and pickers that auto-switch between dropdown and type-ahead at 100+ entries.

It understands the full **unpublished -> dry run -> publish -> push protection** lifecycle and links you to where each UI-only step happens, rather than pretending the API can do it. See the [extension README](.github/extensions/ghsp-custom-pattern-deployment/README.md) for full details and the known API/UI limitations.

<img width="1142" height="993" alt="image" src="https://github.com/user-attachments/assets/2e33a413-e52c-4b99-a308-a55154b23b53" />

---

### 4. 🧪 Code Quality Enablement

> `.github/extensions/code-quality-enablement/`

Bulk enable/disable [GitHub Code Quality](https://docs.github.com/en/code-security/how-tos/maintain-quality-code/enable-code-quality) (and its AI findings) across **every organization in an enterprise**. Code Quality has no org-level API, so per-org actions apply the repo-level `code-quality/setup` API across every repo in that org in the background — orgs can hold 10k+ repos, so per-repo detail is intentionally left out of the table in favor of org-level rollups.

#### Highlights

- **Enterprise-wide table** — load every org in an enterprise, with a live-checkable, sampled Code Quality / AI-findings status per org.
- **Bulk or per-row control** — select orgs with checkboxes and apply an action to all of them, or use the per-row dropdown for a single org.
- **Repository access modes** — mirrors GitHub's own `code-quality/setup` options: All repositories, No repositories, or Matching a filter (name/language/topic); "Selected repositories" is intentionally disabled since there's no bulk API for it.
- **AI findings, separately** — a dedicated AI-scans toggle, with accurate "on / off / n/a (not eligible)" states so repos without a CodeQL-supported language aren't misreported as failed.
- **Billing confirmation** — enabling Code Quality or AI findings first shows a confirmation modal (mirroring GitHub's own billing dialog) with the affected repo/org count and a link to the [billing docs](https://docs.github.com/billing/concepts/product-billing/github-code-quality).
- **Resilient bulk jobs** — background job queue with retries, rate-limit backoff, and per-repo outcome classification (succeeded / not-eligible / policy-blocked / requires-quality-scan / error) surfaced back into the table.
- **Live diagnostics panel** — tails every `gh api` call made by the extension for troubleshooting at scale.

#### Actions

| Action                   | Input                                | Description                                                                                |
|--------------------------|--------------------------------------|--------------------------------------------------------------------------------------------|
| `bulk-toggle` (HTTP API) | `orgs`, `enable`, `filter`, `target` | Queue a background job to enable/disable Code Quality or AI findings across the given orgs |

#### Usage

Ask Copilot to open the canvas:

```text
Open the Code Quality Enablement canvas for my-enterprise
```

The canvas lets you:

- **Load organizations** — list every org in an enterprise slug
- **Check status** — sample repos per org to estimate current Code Quality / AI-findings state
- **Select and apply** — checkbox-select orgs, then Enable all / Disable all / Matching a filter
- **Track progress** — live per-org job progress and outcome breakdown as bulk changes roll out

<img width="902" height="895" alt="image" src="https://github.com/user-attachments/assets/ba3b43b7-d3cb-4a45-ab53-167efedb8360" />

---

## Prerequisites

All extensions require:

- [**Copilot CLI**](https://githubnext.com/projects/copilot-cli) with canvas support
- [**`gh` CLI**](https://cli.github.com/) v2.x, authenticated (`gh auth login`)
- Node.js ≥ 18 (used by the extension runtime)

No `npm install` is needed — the `@github/copilot-sdk` import is resolved automatically by the CLI.

---

## Installation

Extensions in `.github/extensions/` are **auto-discovered** when you open a session in this repository. Simply clone the repo and start a Copilot CLI session:

```bash
git clone https://github.com/advanced-security/ghas-copilot-canvas
cd ghas-copilot-canvas
# open a Copilot CLI session in this directory
```

All four canvases will be available immediately.

---

## Repository structure

```text
.github/extensions/
├── codeql-config-builder/
│   ├── package.json
│   ├── extension.mjs        # Canvas + loopback HTTP server
│   ├── README.md
│   └── public/
│       ├── index.html       # Iframe UI
│       ├── app.js
│       └── styles.css
├── sbom-dependency-audit/
│   └── extension.mjs        # Canvas + SBOM scanning logic
├── ghsp-custom-pattern-deployment/
│   ├── extension.mjs        # Canvas + loopback HTTP server / API endpoints
│   ├── gh.mjs               # gh api wrapper (auth fallback, pagination)
│   ├── patterns.mjs         # patterns.yml discovery + normalization
│   ├── scope.mjs            # scope paths, deep links, list/deploy ops
│   ├── ui.mjs               # Iframe HTML renderer
│   ├── index.html           # UI layout + styling
│   ├── app.js               # Frontend logic
│   ├── js-yaml.mjs          # Vendored YAML parser
│   └── README.md
└── code-quality-enablement/
    ├── extension.mjs        # Canvas + loopback HTTP server / bulk job orchestration
    ├── diagnostics.mjs      # gh api call log tail for the diagnostics panel
    └── public/
        ├── index.html       # Iframe UI
        ├── app.js
        └── styles.css
```

---

## License

This project is licensed under the terms of the MIT open source license. Please refer to the [LICENSE](./LICENSE) file for the full terms.
