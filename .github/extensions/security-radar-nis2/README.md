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
- A recognized CodeQL workflow is positive evidence; an absent recognized filename is **unknown**, not proof that scanning is disabled (default setup and custom workflow names may apply). Dependency deductions retain per-package weights even when packages are grouped into the radar's display-only rollup.
- **Preview the lift**: `toggle_preview` shows the projected score once the critical and high findings are fixed. Mixed dependency rollups retain their Medium/Low package deductions in the preview, board summaries and brief; explicitly selecting the full rollup for a dependency plan still covers all its packages.
- **Copilot drafts**: `draft_plan` (30-day remediation plan), `draft_board`, `ask_auditor`, `draft_dependency_plan`, `draft_evidence` and `ask_copilot`. All are read-only and advisory. Dependency plans include constituent package names even when the radar displays one rollup.
- **Posture brief**: `generate_brief` writes a uniquely named `audit-brief-<repository>-<uuid>.md` snapshot to the extension artifact directory. Later generations never overwrite earlier briefs.
- **Campaigns**: create and track GitHub security campaigns for code scanning alerts (up to 1000 default-branch alerts). For secret scanning, the canvas only prepares selected alert numbers and links to GitHub; it does not create or track secret campaigns.
- Fix execution stays in the radar (`fix_locally`, `assign_copilot` also work from a theme).

## Data and state

- On first open the canvases are empty ("No data yet") and sync from GitHub automatically. Use `refresh` to sync again.
- The repository is resolved from the session checkout with `gh repo view` (ignoring `GH_REPO`), falling back to the `origin` remote. Only `github.com` repositories are supported: both resolution paths verify the host, and API calls explicitly target it. Resolved and restored repository identifiers are normalized to lowercase.
- A GitHub sync is cached per repository under `~/.copilot/extensions/security-radar-nis2/artifacts/` (or `$COPILOT_HOME`) and only used when it matches the current repository.
- Each repository has its own `radar-cache-<encoded-owner%2Frepo>.json`; the legacy shared cache is not restored. Changing repository identity clears alert data, evidence settings and panel selections before loading the new repository. Unconfirmed campaign and fix-session receipts are preserved; fix links from other repositories are not displayed.
- Cached security metadata is owner-readable only. Containment annotations are saved separately per repository using queued atomic writes and unique temporary files; legacy unscoped annotations are ignored. Annotations do not close GitHub alerts, remove campaign scope or change posture scores.
- Copilot panel questions share one chat session: wait for an answer before asking in either canvas. Repository-dependent actions are serialized with refresh across both canvases, from repository resolution through action completion. Read-only, negated or ambiguous free-form requests do not launch fix sessions; use **Fix locally** for explicit execution.
- If an existing fix-session or campaign ledger cannot be read or validated, extension initialization fails without overwriting it. Inspect the saved ledger before reloading; do not discard unconfirmed receipts. Reset preserves unknown fix launches so late receipts can still recover them without launching duplicate sessions.
- An unknown fix launch can be released only after explicitly confirming that the session list contains no dedicated fix session for that exact request. Releasing the receipt does not retry: **Fix locally** becomes available for a separate, deliberate launch. A confirmed session receipt remains confirmed even if the coordinator's delivery later reports an error.
- Paginated alert and campaign listings have a two-minute budget for the complete listing, not just one page. Radar layout is reused until its findings or layout seed changes; live annotations and links are still updated on each state read.
- Canvas HTTP routes require a per-instance capability URL and the exact loopback Host. Foreign Origins are rejected; actions require same-origin JSON. State and event streams use the same capability.
- All three alert listings project their required metadata inside `gh`, before stdout reaches Node's buffer. Code scanning retains rule/location, branch and assignee metadata; Dependabot retains package, manifest and severity metadata; secret scanning retains only alert number, state, type, display name and URL. Full advisory text, snippets and secret values are excluded. Campaign listings remain unprojected. Cached metadata, posture briefs and fix-session ledgers use owner-only permissions (`0600`).
- An explicit disabled-feature response (HTTP 403/404) counts as empty; all three disabled types still fail the sync. A generic 404 or other access error is not proof of zero alerts: the sync fails and retains the last matching cache, if any, marked stale rather than live.
- Campaign managers may use ordinary or enterprise-managed GitHub logins, including the managed-user underscore suffix.

## Requirements

- Copilot CLI / GitHub Copilot app with canvas support.
- Authenticated `gh` CLI with access to the repository's code scanning, Dependabot and secret scanning alerts (`security_events` / `repo` scope as applicable).
- Dedicated fix sessions (`request_copilot`, `fix_locally`) need the GitHub Copilot app, which provides session creation.
- Copilot Autofix assignment requires code scanning and Copilot Autofix to be available for the repository.

## Tests

```bash
node --test lib/*.test.mjs
```
