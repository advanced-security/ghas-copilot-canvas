# Security Radar & NIS2 / DORA Posture

Two Copilot canvases that turn the **open GitHub Advanced Security alerts of the current repository** into something you can read at a glance and act on. They share one extension, one alert sync and one set of fix and campaign workflows.

> Alert metadata is read with `gh api`. Secret values are never loaded: only the secret type and alert number are used.

## TL;DR

| Canvas | id | What it does |
| --- | --- | --- |
| **Attack surface radar** | `attack-surface-radar` | A radar of your open code scanning, Dependabot and secret scanning alerts. Each blip is a group of alerts (one per code scanning rule, secret type or vulnerable package), placed on rings by severity. Select a blip to have Copilot explain it, assess its priority, suggest a fix or answer a question, then fix it or assign it to Copilot Autofix. |
| **NIS2 / DORA posture** | `compliance-scoreboard` | An *illustrative* posture score built from the same alerts plus repository evidence, mapped to five control themes. Preview the projected score, draft plans and evidence checklists with Copilot, generate a posture brief and run security campaigns. **Not a legal assessment.** |

## Attack surface radar

- **Radar view**: critical findings sit in the inner ring, lower severities further out. Totals per alert type are shown as KPIs.
- **Ask Copilot** about one finding: `explain_finding`, `assess_priority` (read-only, advisory, never changes GitHub severity), `suggest_fix` (strategy, no code) and free-form `ask_copilot`. Answers appear in the panel and fall back to an offline answer if Copilot does not reply in time.
- **Fix locally** (`request_copilot`): launches a dedicated, isolated worktree session to remediate one non-secret finding. Secrets are never "fixed" from the panel.
- **Assign to Copilot Autofix** (`assign_copilot`): assigns one code scanning alert through the GitHub REST API. Uses AI credits.

## NIS2 / DORA posture

- **Five control themes**: vulnerability handling, supply-chain risk, secrets and access, secure change control and incident-response evidence, each mapped to illustrative NIS2 (EU 2022/2555) and DORA (EU 2022/2554) articles.
- **Score** built from open findings (severity, repeats, exposed secrets, vulnerable packages) and **repository evidence**: CodeQL workflow, `SECURITY.md`, Dependabot config and security updates, secret push protection, validity checks, `CODEOWNERS` and an incident-response runbook. Files are checked in the checkout; settings are read from GitHub.
- **Preview the lift**: `toggle_preview` shows the projected score once the critical and high findings are fixed.
- **Copilot drafts**: `draft_plan` (30-day remediation plan), `draft_board`, `ask_auditor`, `draft_dependency_plan`, `draft_evidence` and `ask_copilot`. All are read-only and advisory.
- **Posture brief**: `generate_brief` writes `audit-brief.md` to the extension artifact directory.
- **Campaigns**: create and track GitHub security campaigns for code scanning or secret scanning alerts (up to 1000 alerts, default-branch alerts for code).
- Fix execution stays in the radar (`fix_locally`, `assign_copilot` also work from a theme).

## Data and state

- On first open the canvases are empty ("No data yet") and sync from GitHub automatically. Use `refresh` to sync again.
- The repository is resolved from the session checkout with `gh repo view`, falling back to the `origin` remote.
- A GitHub sync is cached per repository under `~/.copilot/extensions/security-radar-nis2/artifacts/` (or `$COPILOT_HOME`) and only used when it matches the current repository.
- If an alert type is not enabled (HTTP 403/404), it counts as empty; the sync only fails if all three are unavailable.

## Requirements

- Copilot CLI / GitHub Copilot app with canvas support.
- Authenticated `gh` CLI with access to the repository's code scanning, Dependabot and secret scanning alerts (`security_events` / `repo` scope as applicable).
- Dedicated fix sessions (`request_copilot`, `fix_locally`) need the GitHub Copilot app, which provides session creation.
- Copilot Autofix assignment requires code scanning and Copilot Autofix to be available for the repository.

## Tests

```bash
node --test lib/*.test.mjs
```
