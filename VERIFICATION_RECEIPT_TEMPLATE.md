# Exact-Tag Verification Receipt Template

**Purpose:** complete this as a separate asset only after an exact v0.3 tag has been created. Do not prefill future publication events inside the tag.

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

If the environment requires it, record `npx playwright install chromium` separately as browser setup rather than as a test.

## Behavioral test inventory

| Lane | Exact count | Result |
|---|---:|---|
| Core | 46 |  |
| API/server | 13 |  |
| SDK | 12 |  |
| Operator UI | 3 |  |
| zkYA component | 9 |  |
| Scanner regression | 9 |  |
| Release-tooling regression | 7 |  |
| Chromium E2E | 1 |  |

Do not count format, security, typecheck, build, package, or audit gates as tests.

## Exact-tag assets

List only assets that exist and were hashed after construction. The receipt itself must not claim to contain its own final digest.

| Asset | SHA-256 | Size |
|---|---|---:|
|  |  |  |

## Explicit stage boundary

This receipt verifies the exact tag locally. It contains **no publication, GitHub immutable-state, public URL availability, logged-out download, archive readback, merge-protection, tag-CI, independent-review, or npm-publication proof**.

If publication later occurs, create a separate dated post-publication sidecar for GitHub API state, logged-out download, checksum, and extraction/readback evidence. Do not edit this tagged template or claim that future sidecar evidence existed inside the tag.

## Limitations

Integrated local reference only. No production identity/KYC/AML, zero-knowledge verification, authentication, deployment, durable distributed state, protected execution, adoption, or external validation is implied.
