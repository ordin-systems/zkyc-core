# Exact-Tag Verification Receipt Template

**Purpose:** complete this as a separate asset only after the exact tag named below exists. Do not prefill future publication events inside the tag.

- **Repository:** `https://github.com/ordin-systems/zkyc-core`
- **Exact tag:** `<existing tag>`
- **Tag commit:** `<exact SHA resolved from tag>`
- **Tree:** `<exact tree SHA>`
- **Verified at:** `<UTC timestamp after tag creation>`
- **Node:** `<version>`
- **npm:** `<version>`
- **OS/architecture:** `<values>`
- **Lockfile SHA-256:** `<hash>`

## Commands

Start with the locked, script-disabled install. Record actual exit codes and results.

| Command | Exit | Result |
|---|---:|---|
| `npm ci --ignore-scripts` |  |  |
| `npm run format:check` |  |  |
| `npm run security:check` |  |  |
| `npm run typecheck` |  |  |
| `npm run typecheck:workspaces` |  |  |
| `npm test` |  |  |
| `npm run build:all` |  |  |
| `npm run test:browser` |  |  |
| `npm run package:check` |  |  |
| `npm audit --audit-level=high` |  |  |

If the environment requires it, record `npx --no-install playwright install chromium` separately as browser setup rather than as a test.

## Behavioral test inventory

Populate counts from the actual exact-tag execution rather than copying candidate-era values.

| Lane | Actual count | Result |
|---|---:|---|
| Core |  |  |
| API/server |  |  |
| SDK |  |  |
| Operator UI |  |  |
| zkYA component |  |  |
| Scanner regression |  |  |
| Release-tooling regression |  |  |
| Chromium E2E |  |  |

Do not count format, security, typecheck, build, package, or audit gates as tests.

## Exact-tag assets

List only assets that exist and were hashed after construction. The receipt itself must not claim to contain its own final digest.

| Asset | SHA-256 | Size |
|---|---|---:|
|  |  |  |

## Explicit stage boundary

This receipt verifies the exact tag locally. It contains **no publication, GitHub immutable-state, public URL availability, logged-out download, archive readback, merge-protection, tag-CI, independent external review, or npm-publication proof**.

If publication later occurs, create a separate dated post-publication sidecar for GitHub API state, logged-out download, checksum, and extraction/readback evidence. Do not edit this tagged template or claim that future sidecar evidence existed inside the tag.

## Limitations

Integrated local reference only. No production identity/KYC/AML, zero-knowledge verification, authentication, deployment, durable distributed state, protected execution, adoption, or external validation is implied.
