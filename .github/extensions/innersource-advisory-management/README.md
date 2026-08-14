# Innersource Advisory Management

A Copilot canvas for managing GitHub innersource security advisories. It provides a GitHub-style form over the OSV payload used by the innersource vulnerability sync API.

## Capabilities

- Load existing GHIS advisories from either an enterprise or organization GraphQL scope.
- Keep the source and deployment target independent, including organization-to-enterprise and cross-organization workflows.
- Create or edit OSV 1.4 advisory data with supported ecosystems, version ranges, references, CVE aliases, withdrawal dates, raw JSON import/export, and a one-click copy of GitHub's documented minimal OSV sample for new drafts.
- Calculate a CVSS 3.1 base vector, score, and qualitative severity.
- Validate GitHub-specific OSV requirements and field limits before deployment.
- Generate a short-lived installation token from an App ID and selected PEM private key without persisting either credential.
- Create, update, or withdraw an advisory through the asynchronous sync API and poll the job to completion.
- Inspect a bounded, in-memory API activity tail with redacted request bodies, response JSON, status codes, safe response headers, and GitHub request IDs.
- Keep private preview organization deployment controls hidden until **Enable preview features** is switched on.

## Scope support

| Scope | Load | Deploy |
|---|---|---|
| Enterprise | GA | GA through the published REST API |
| Organization | GA | Private preview; requires account enablement |

Loading existing advisories is GA for both scopes. Enterprise deployment is GA and distributes advisories across an entire enterprise through the published REST API. Organization deployment is a private preview, remains hidden in the canvas until preview features are enabled, and normally returns `404` unless GitHub has enabled organization sync for that account.

## Authentication

Loading uses the current authenticated `gh` CLI user and the GraphQL feature header `GraphQL-Features: innersource_alerting`. The user token needs `read:org` for organization sources and `read:enterprise` (or `admin:enterprise`) for enterprise sources. If an environment `GH_TOKEN` lacks the required scope, the extension retries with the credential stored by `gh auth login`.

Deployment does **not** support personal access tokens or OAuth tokens. Use a GitHub App installation token with:

- `enterprise_innersource_vulnerabilities:write` for enterprise targets
- `organization_innersource_vulnerabilities:write` for organization targets in the private preview

Provide the token in any of these ways:

1. Set `GH_INNERSOURCE_TOKEN` before starting Copilot CLI.
2. Paste it into the canvas password field for the current deployment request. The canvas does not persist or log the value.
3. Expand **Generate an installation token**, enter the App ID or client ID, and select the App's PEM private key. The canvas creates a JWT, discovers the installation for the selected target, verifies write permission, and generates an installation token that remains only in server memory until it expires or is cleared.

The generation flow requires the App ID (or client ID) and private key. It does **not** use the client secret. The App must already be installed on the selected target. Installation IDs are discovered automatically through `GET /app/installations`; an explicit installation ID can be supplied when needed. Generated installation tokens expire after one hour.

The browser does not expose the private key's full local path. It uploads the selected PEM contents only to the canvas's loopback server for in-memory JWT signing; the key is not written to disk, returned to the browser, or logged.

The top-right authentication summary includes an information popover showing the OAuth scopes reported for the active `gh` credentials. When the canvas holds a generated installation token, it also shows the App, installation ID, target, expiry, and granted App permissions without exposing the token.

## API activity log

Expand **API activity** at the bottom of the canvas to inspect GraphQL, REST, and GitHub App calls. The log includes request and response JSON, HTTP status, duration, `Location`, `Retry-After`, and `X-GitHub-Request-Id` when GitHub returns them. It retains the most recent 100 entries in server memory and is cleared when the canvas closes.

Authorization headers, installation tokens, App JWTs, PEM private keys, passwords, cookies, and token-shaped strings are redacted before entries reach the browser. Large request or response sections are truncated. **Copy latest response** copies the exact retained response body, which is useful for async sync-result JSON.

See [Generating an installation access token for a GitHub App](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

## Agent-facing actions

| Action | Purpose |
|---|---|
| `list_advisories` | List and optionally filter advisories in an organization or enterprise scope. |
| `validate_advisory` | Validate one OSV payload against GitHub requirements. |
| `sync_advisory` | Sync one advisory and wait for completion using `GH_INNERSOURCE_TOKEN`. |

## Open input

The canvas accepts optional `sourceType`, `sourceSlug`, `targetType`, `targetSlug`, `previewFeatures`, and `advisoryId` values. An organization target automatically enables preview controls. For example, an agent can open an organization source and enterprise target:

```json
{
  "sourceType": "organization",
  "sourceSlug": "octo-org",
  "targetType": "enterprise",
  "targetSlug": "octo-enterprise"
}
```

## Files

```text
.github/extensions/innersource-advisory-management/
|-- extension.mjs
|-- diagnostics.mjs
|-- diagnostics.test.mjs
|-- app-auth.mjs
|-- app-auth.test.mjs
|-- github.mjs
|-- github.test.mjs
|-- advisory.mjs
|-- advisory.test.mjs
|-- package.json
|-- README.md
`-- public/
    |-- index.html
    |-- app.js
    `-- styles.css
```
