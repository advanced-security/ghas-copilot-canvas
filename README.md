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

## Prerequisites

Both extensions require:

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

Both canvases will be available immediately.

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
└── sbom-dependency-audit/
    └── extension.mjs        # Canvas + SBOM scanning logic
```

---

## License

See [LICENSE](LICENSE) for details.
