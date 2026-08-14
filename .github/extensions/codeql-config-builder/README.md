# CodeQL Config Builder — Copilot CLI canvas extension

A focused Copilot CLI canvas for **building and committing CodeQL configuration YAML files** (`.github/codeql/codeql-config.yml`). All fields documented at <https://gh.io/codeql-config> are supported.

> Repo / Org / Enterprise GHAS enablement (toggling Advanced Security, secret scanning, push protection, Dependabot, etc.) lives in a separate canvas — this one is intentionally scoped to *just* CodeQL configuration.

## Install

This extension is committed at **project scope** at `.github/extensions/codeql-config-builder/`. Once the repo is cloned, it's auto-discovered by Copilot CLI when you start a session in this workspace. The `@github/copilot-sdk` import is resolved automatically by the CLI — no `npm install` needed.

External tool required: [`gh`](https://cli.github.com/) v2.x, authenticated (`gh auth login`).

## What it builds

The form covers every documented CodeQL config field:

- `name`
- `disable-default-queries`
- `threat-models` (dropdown: `remote` / `local`)
- `queries` (list of `uses` + optional `name`, with autocomplete for the standard query suites)
- `packs` (per-language with a real language picker — supports the 10 official CodeQL languages; pack-ref autocomplete for the `codeql/*-queries` packs)
- `paths`, `paths-ignore`
- `query-filters` (`include` / `exclude` × key/value, with smart autocomplete that adapts the value suggestions to the chosen key)

## What it does

- **Preview YAML** — render the generated YAML in-panel.
- **Download YAML** — save `codeql-config.yml` locally.
- **Load existing** — fetch the current file from the target repo (helpful before editing).
- **Commit to repo** — `PUT /repos/{owner}/{repo}/contents/<path>` via `gh api`, auto-detecting the existing `sha` so updates don't 422.

## Agent-facing actions

| Action | Input | Description |
| --- | --- | --- |
| `load_config` | `{ owner, repo, branch?, path? }` | Read an existing CodeQL config from a repo. |
| `write_codeql_config` | `{ owner, repo, branch?, path?, yamlContent, message? }` | Commit a CodeQL config YAML. |

## Files

```text
.github/extensions/codeql-config-builder/
├── package.json
├── extension.mjs      # canvas + loopback HTTP server (uses `gh api`)
├── README.md
└── public/
    ├── index.html     # iframe UI
    ├── app.js
    └── styles.css
```
