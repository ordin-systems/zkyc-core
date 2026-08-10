# Reproducibility

## Requirements

- Node.js 20.19.x or Node.js 22.12.0 or newer;
- npm with lockfile/workspace support;
- Playwright Chromium for the browser gate.

## Exact candidate scope

The v0.3 executable baseline is `55d15981cf7f45e441205eb96f5aae79e58d00ae`. This documentation is a forward documentation-only successor to that runtime. Neither identifier is a release tag.

## Clean local verification

From a fresh copy of the exact candidate commit, start with:

```bash
npm ci --ignore-scripts
npm run format:check
npm run security:check
npm run typecheck
npm run typecheck:workspaces
npm test
npm run build:all
npm run test:browser
npm run package:check
npm audit --audit-level=high
```

`npm run verify` composes the same root gates. If Playwright Chromium is absent, install it separately after the lockfile install with:

```bash
npx --no-install playwright install chromium
```

That download is an environment prerequisite. It is not a passing test or release receipt.

## Behavioral test inventory

- core: 46;
- API/server: 13;
- SDK: 12;
- operator UI: 3;
- zkYA component: 9;
- scanner regression: 9;
- release-tooling regression: 7;
- Chromium E2E: 1.

Formatting, security scanning, core/workspace typechecks, core/workspace builds, package proof, and dependency audit are distinct checks, not tests.

## What the gates exercise

- credential v2, typed principals, direct/delegated evaluation, one-hop attenuation, policy pinning, and reason-coded denial;
- step-up v2 human/type/capability/action/resource binding and revalidation;
- receipt v2 signature/binding validation, authority revalidation, and replay rejection;
- strict API and SDK transport/schema behavior;
- versioned lifecycle transcripts through both API and SDK runners;
- both React UIs through component tests;
- the built zkYA UI through a real local Chromium page, browser SDK, same-origin proxy, and loopback API.

## Determinism and local runtime

Core/API/SDK transcript tests use fixed identifiers, timestamps, policies, and non-production keys with injected clocks. The Chromium smoke starts a compiled API on IPv4 loopback using an ephemeral port and a built zkYA preview server. UI-only wall-clock values are for local demonstration and do not alter the deterministic fixture evidence.

No database, external model, live credential service, production secret, or public network service is required.

## Later release evidence

`VERIFICATION_RECEIPT_TEMPLATE.md` is for a later exact tag. A completed receipt must be created after the exact tag exists and may record commit/tree, environment, lockfile, commands, test counts, and separately generated asset hashes. It must not claim publication or logged-out readback.

After publication, a separate dated sidecar may record immutable-release API state, logged-out download, checksum, and extraction verification. That future audit cannot be prefilled inside the tag or made self-referential.

A passing local build is not deployment, production readiness, release, publication, or external validation.
