# zKYC Core

**Deterministic Agent Identity and Action-Authority Reference Stack**

> **Status:** integrated local `v0.3.1` corrective candidate. It is not yet merged, tagged, released, or published. Historical immutable [`v0.3.0`](https://github.com/ordin-systems/zkyc-core/releases/tag/v0.3.0) remains unchanged at commit `c67f16c39d67b4c56c88d06c9738d4a164d2a27e` and tree `e73f3401718d01a7e5bcca1aa84b728e7fa55ccc`.

zKYC Core evaluates typed principals and direct or delegated authority against exact credential, action, resource, and versioned-policy scope. It returns reason-coded `ALLOW`, `DENY`, or `STEP_UP` decisions and supports one-time, authority-bound consumption.

The current candidate includes:

- `HUMAN`, `ORGANIZATION`, and `AGENT` principal types;
- scoped credential v2 records and one-hop attenuated delegation grants;
- separate acting-subject and grantor credentials in delegated mode, with no grantor-affiliation transfer;
- policy-pinned delegation, expiry/revocation revalidation, and human-only exact-scope step-up;
- authority-bound HMAC-SHA256 receipt v2 verification and replay rejection;
- Hono API and a strictly runtime-validated TypeScript SDK with exact request/response correlation across success and denial outcomes;
- monotonic receipt projection with durable `consumptionStatus` separated from the latest accepted or rejected attempt;
- operator cockpit and zkYA onboarding reference UIs;
- executable versioned lifecycle transcripts and one real local Chromium end-to-end test;
- clean-build, fail-closed archive/scanner/package checks with blank-consumer package proof.

Historical releases, including [`v0.2.1-full-stack-reference`](https://github.com/ordin-systems/zkyc-core/releases/tag/v0.2.1-full-stack-reference) and `v0.3.0`, remain immutable and are not retagged or rewritten by this forward correction.

## Workspace map

- `src/` — deterministic authority core;
- `apps/core-api/` — trusted Hono transport adapter and retained onboarding views;
- `packages/sdk/` — browser-compatible client with exact runtime response validation;
- `apps/operator-ui/` — authority lifecycle reviewer cockpit;
- `apps/zkya-onboarding/` — zkYA / Know-Your-Agent onboarding reference UI;
- `fixtures/` — deterministic core and versioned full-stack transcripts;
- `e2e/` and `scripts/full-stack-smoke.mjs` — real local SDK/HTTP/Chromium smoke path;
- `test/` and workspace test directories — executable behavioral evidence.

## Review the candidate

From the exact candidate checkout, begin with the lockfile-only install and run the root gates explicitly:

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

`npm run verify` composes those gates. Typecheck, build, format, security, package, and dependency-audit gates are checks, not tests.

The browser test requires Playwright Chromium. If it is not already present, run `npx --no-install playwright install chromium` after `npm ci --ignore-scripts` and before `npm run test:browser`. CI uses `npx --no-install playwright install --with-deps chromium`. Browser installation is an environment prerequisite, not evidence that the test passed.

Current executable inventory for the `v0.3.1` candidate is: core 46, API/server 13, SDK 223, operator UI 3, zkYA component 9, scanner regression 9, release-tooling regression 8, and Chromium E2E 1.

## Run the local interfaces

Build the workspaces:

```bash
npm run build:all
```

Start the loopback API with a generated local-only HMAC key:

```bash
export ZKYC_RECEIPT_HMAC_KEY="$(openssl rand -hex 32)"
npm run start -w @ordin/zkyc-core-api-reference
```

In another terminal, run either reviewer UI:

```bash
npm run dev -w @ordin/zkyc-operator-ui-reference
# or
npm run dev -w @ordin/zkya-onboarding-reference
```

Both UIs call the local SDK/API stack. They display authority state and one-time consumption; they do not verify identity or execute protected actions.

## Evidence chain

`UI/SDK → Hono trusted adapter → deterministic evaluator → reason-coded decision → receipt or bound step-up → current-authority revalidation → one-time consumption`

Start with:

- `docs/principal-and-delegation-model.md`
- `docs/zkya-onboarding-reference.md`
- `docs/full-stack-reference.md`
- `docs/api-contract.md`
- `docs/reviewer-walkthrough.md`
- `docs/evidence-map.md`
- `CLAIMS_AND_LIMITATIONS.md`
- `REPRODUCIBILITY.md`
- `PROVENANCE.md`

## Authorship and automated review provenance

**Mike “Mizzy” Barrera and Monique Abrams — joint authors and co-architects.**

Automated AI assistants were used off-GitHub to support implementation and perform separate specification and code-quality review passes. Their outputs informed maintainer decisions and are process provenance only. They are not project authors, owners, external validators, or third-party security auditors, and automated review is not independent external approval.

## Critical boundaries

This is an integrated local reference candidate, not production identity, KYC/AML, zero-knowledge verification, authentication, deployment, durable/distributed state, protected execution, adoption, or external validation. The API is unauthenticated and in-memory and must not be deployed as-is. `zkPassProofId` and related values remain non-authoritative metadata.

No npm registry publication is authorized. No license is granted unless and until ORDIN publishes an explicit license file.
