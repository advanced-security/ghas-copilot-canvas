# GHAS Copilot Canvas Extensions

A collection of **GitHub Copilot CLI canvas extensions** for GitHub Advanced Security (GHAS) workflows. Canvases are interactive side-panel UIs that appear inside the Copilot CLI app — they let you interact with rich forms and live data without leaving your terminal workflow.

---

## Extensions

### 1. 🔍 CodeQL Config Builder

> `.github/extensions/codeql-config-builder/`

A form-driven builder for **CodeQL configuration YAML files** (`.github/codeql/codeql-config.yml`). Every field documented at [gh.io/codeql-config](https://gh.io/codeql-config) is supported.

#### What you can build

| Field | Details |
|---|---|
| `name` | Free-text name for the config |
| `disable-default-queries` | Toggle the built-in query suite |
| `threat-models` | Dropdown: `remote` / `local` |
| `queries` | List of `uses` entries with optional `name`; autocomplete for standard suites |
| `packs` | Per-language packs with a language picker (all 10 official CodeQL languages) |
| `paths` / `paths-ignore` | Inclusion/exclusion path lists |
| `query-filters` | `include` / `exclude` rules with smart key→value autocomplete |

#### Actions

| Action | Required input | Description |
|---|---|---|
| `load_config` | `owner`, `repo` | Fetch the existing config from a repo |
| `write_codeql_config` | `owner`, `repo`, `yamlContent` | Commit the YAML to the repo |

Both actions accept optional `branch` and `path` parameters.

#### Usage

Ask Copilot to open the canvas:

```
Open the CodeQL Config Builder for owner/my-repo
```

Or trigger it directly for a specific repo:

```
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

| Action | Input | Description |
|---|---|---|
| `run_scan` | `org`, `dependency` | Scan all repos in an org and return a Markdown report |

Both `org` and `dependency` are also accepted as canvas open inputs to pre-fill the form.

#### Usage

Ask Copilot to open the canvas:

```
Audit adrienpessu-octodemo for @antv/data-set
```

Or start a scan via agent action:

```
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

Bulk-deploys **secret-scanning custom patterns** to an **enterprise, organization, or repository**. It loads `patterns.yml` configs (for example the samples in [advanced-security/secret-scanning-custom-patterns](https://github.com/advanced-security/secret-scanning-custom-patterns), or a local path) and turns the slow, one-at-a-time UI workflow into a browse, filter, select, deploy flow over the private-preview custom-patterns REST API.

#### Highlights

- **Load from anywhere** — recursive scan of a repo for every `patterns.yml`, or a local path, with branch/ref override.
- **Browse + inspect** — expandable tree grouped by config file, showing type, regex, delimiters, "must not match" rules, and `test:` cases with the offset substring highlighted.
- **Deploy at three levels** — Enterprise / Org / Repo, with per-level API paths and UI deep links.
- **Load deployed state** — live **State** (published/unpublished) and **Push Protection** status per pattern, deep-linked to the right settings page.
- **Bulk deploy** — select across files and create many patterns at once (created as unpublished, per the API).
- **Built for scale** — server-side repo search (5k+ repo orgs resolve in seconds) and pickers that auto-switch between dropdown and type-ahead at 100+ entries.

It understands the full **unpublished -> dry run -> publish -> push protection** lifecycle and links you to where each UI-only step happens, rather than pretending the API can do it. See the [extension README](.github/extensions/ghsp-custom-pattern-deployment/README.md) for full details and the known private-preview API limitations.

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

All three canvases will be available immediately.

---

## Repository structure

```
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
└── ghsp-custom-pattern-deployment/
    ├── extension.mjs        # Canvas + loopback HTTP server / API endpoints
    ├── gh.mjs               # gh api wrapper (auth fallback, pagination)
    ├── patterns.mjs         # patterns.yml discovery + normalization
    ├── scope.mjs            # scope paths, deep links, list/deploy ops
    ├── ui.mjs               # Iframe HTML renderer
    ├── index.html           # UI layout + styling
    ├── app.js               # Frontend logic
    ├── js-yaml.mjs          # Vendored YAML parser
    └── README.md
```

---

## License

See [LICENSE](LICENSE) for details.
