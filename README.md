# zKYC Core

**Deterministic Agent Identity and Action-Authority Reference Stack**

zKYC Core evaluates a principal, credential and requested action against versioned policy; returns a reason-coded `ALLOW`, `DENY` or `STEP_UP`; and supports bound, one-time authority consumption.

The v0.2 successor adds a sanitized full-stack demonstration around the audited core:

- Hono reference API;
- browser-compatible TypeScript SDK;
- React/Vite operator cockpit;
- reason-coded in-memory decision/receipt history;
- deterministic full-stack fixtures;
- API/SDK contract tests and automated UI interaction coverage;
- CI-backed core, API, SDK and UI builds.

The immutable [`v0.1.0-reference`](https://github.com/ordin-systems/zkyc-core/releases/tag/v0.1.0-reference) release remains unchanged.

## Workspace map

- `src/` — deterministic authority core;
- `apps/core-api/` — trusted Hono transport adapter;
- `packages/sdk/` — typed browser-compatible client;
- `apps/operator-ui/` — React/Vite reviewer cockpit;
- `fixtures/` — deterministic core and full-stack cases;
- `test/`, `apps/core-api/test/`, `packages/sdk/test/` — executable evidence.

## What v0.2 proves

- configurable action sensitivity tiers and content-versioned policy;
- credential issuance, expiry and revocation checks;
- reason-coded `ALLOW`, `DENY` and `STEP_UP` decisions;
- bound human approval and rejection workflows;
- HMAC-SHA256 receipts issued only from same-transaction `ALLOW` decisions;
- complete receipt binding, credential recheck and one-time replay consumption;
- step-up creation only from retained evaluator output;
- typed API/SDK contracts and clean React/Vite production build;
- deterministic fixtures plus negative-path, tamper, redirect, provenance, UI-state and concurrency tests.

## One-command verification

```bash
npm ci --ignore-scripts
npm run verify
```

`verify` runs repository formatting and publication-safety scans, strict core/workspace typechecks, core/API/SDK/UI and scanner regression tests, every workspace build, archive membership plus isolated-import checks, and `npm audit`.

## Local reviewer cockpit

Build the stack:

```bash
npm ci --ignore-scripts
npm run build:all
```

Start the reference API with a generated local-only HMAC key:

```bash
export ZKYC_RECEIPT_HMAC_KEY="$(openssl rand -hex 32)"
npm run start -w @ordin/zkyc-core-api-reference
```

In another terminal:

```bash
npm run dev -w @ordin/zkyc-operator-ui-reference
```

The UI proxies `/api` to the local Hono adapter. It does not expose signing keys or execute protected actions.

## Evidence chain

`operator/SDK → Hono trusted adapter → deterministic evaluator → reason-coded decision → receipt or bound step-up → complete verification → one-time consumption`

See:

- `docs/full-stack-reference.md`
- `docs/api-contract.md`
- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/evidence-map.md`
- `REPRODUCIBILITY.md`
- `CLAIMS_AND_LIMITATIONS.md`
- `PROVENANCE.md`

## Critical boundaries

This is a **reference implementation**, not production infrastructure. The Hono API intentionally omits authentication, tenancy, rate limiting, durable storage and distributed coordination. Do not deploy it as-is.

Decision logs, credentials, step-up state and nonces use in-memory reference adapters. HMAC receipts assume a shared-secret trust domain. The UI demonstrates authority state only; it never executes a requested action.

`zkPassProofId` and similar identifiers are non-authoritative contextual metadata. This repository does not verify zero-knowledge proofs or perform real-world KYC/AML.

No license is granted unless and until ORDIN publishes an explicit license file.
