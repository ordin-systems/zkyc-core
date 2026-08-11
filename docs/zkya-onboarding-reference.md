# zkYA Onboarding Reference

## Purpose

`apps/zkya-onboarding` is an executable local reference for presenting Know-Your-Agent authority state through the real zKYC SDK and Hono API. It is post-CV candidate implementation evidence, not proof that the frozen CV had an executable zkYA product.

The interface is explicitly labeled local/reference-only. It does not onboard a real identity, verify KYC/AML or ZK proofs, authenticate a tenant, or execute an eligible action.

## Retained onboarding projection

After evaluation, the API retains the exact decision and its authority artifacts in memory. The UI fetches:

`GET /zkya/onboarding-views/:decisionLogId`

The versioned view presents:

- current `ACTIVE`, `EXPIRED`, `REVOKED`, or `INVALID` verification status;
- principal ID, exact principal type, and credential-bound affiliations;
- `DIRECT` or `DELEGATED` authority mode;
- delegated grantor ID/type, delegation ID, exact capabilities/actions/resources, and current delegated-scope status;
- exact action/resource eligibility and reason code;
- required approval state: `NOT_REQUIRED`, `PENDING`, `APPROVED`, `REJECTED`, or `EXPIRED`;
- receipt projection on two independent axes:
  - durable `consumptionStatus`: `NOT_ISSUED`, `UNCONSUMED`, or `CONSUMED`;
  - `lastAttempt`: `NONE`, `ACCEPTED / RECEIPT_VALID`, or `REJECTED` with the exact associated non-malformed receipt failure;
- exact policy ID and version.

The projection rechecks retained credential, grantor, delegation, expiry, and revocation state when read. It is a current in-process view, not a durable credential or audit ledger.

## Executable scenarios

The candidate UI covers direct allow and receipt replay, delegated organization scope, human step-up approval/rejection, credential action/resource mismatch, and revoked delegation paths. It shows the full effective scope without treating grantor affiliations as delegate affiliations.

Receipt consumption submits the complete v2 authority binding. A successful first consume changes durable `consumptionStatus` to `CONSUMED` and records `ACCEPTED / RECEIPT_VALID`. Replay returns `RECEIPT_REPLAYED`; durable consumption remains `CONSUMED` while `lastAttempt` becomes `REJECTED / RECEIPT_REPLAYED`. Malformed or unassociated receipt input does not alter either retained projection axis. Human resolution uses a separate registered `HUMAN` approver credential with the required capability and exact step-up action/resource scope.

## Runtime chain

```text
built zkYA React UI
        ↓ browser SDK
same-origin /api proxy
        ↓
loopback Hono API
        ↓
core credential/delegation/policy evaluation
        ↓
retained onboarding view + one-time receipt/step-up consumption
```

`npm run test:browser` builds and starts this chain locally using an ephemeral API port and Playwright Chromium. The one Chromium E2E test exercises direct receipt consumption/replay, delegated presentation, step-up approval/rejection, scope denials, and revoked delegation status through real browser HTTP calls.

Component coverage is separate: the zkYA workspace has 9 component tests. The Chromium lane has 1 E2E test. Build and typecheck are checks rather than tests.

## Run locally

After `npm ci --ignore-scripts` and `npm run build:all`, start the loopback API with a generated HMAC key and run:

```bash
npm run dev -w @ordin/zkya-onboarding-reference
```

The Vite development server proxies `/api` to the local API. For the automated browser lane, install Chromium separately if required with `npx playwright install chromium`, then run `npm run test:browser`.

## Evidence and maturity boundary

This is an integrated local reference candidate. It has not been pushed, merged, tagged, released, published, independently approved, or deployed. It establishes no production identity/KYC/AML, ZK verification, authentication, durability, protected execution, adoption, or external validation.
