# Reviewer Walkthrough

This walkthrough reviews the integrated local v0.3 candidate. It does not assume or claim a push, merge, tag, release, public URL, immutable artifact, CI result, or independent approval.

## 1. Install and run exact root gates

Start with the script-disabled lockfile install:

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

If Playwright Chromium is absent, run `npx --no-install playwright install chromium` separately after `npm ci --ignore-scripts` and before the browser gate. Installation is a prerequisite, not a passing test.

`npm run verify` composes the root gates. Do not count formatting, security, typecheck, build, package, or dependency audit as tests.

## 2. Confirm behavioral counts

Expected at executable baseline `55d15981cf7f45e441205eb96f5aae79e58d00ae`:

- core 46;
- API/server 13;
- SDK 12;
- operator UI 3;
- zkYA component 9;
- scanner regression 9;
- release-tooling regression 7;
- Chromium E2E 1.

This walkthrough is a forward documentation-only successor to that runtime baseline.

## 3. Inspect typed and delegated authority

Read in order:

1. `src/domain.ts` — principal types and strict domain validation;
2. `src/credentials.ts` — credential v2 and exact scope hash;
3. `src/delegations.ts` — one-hop grant, attenuation, policy binding, and revocation;
4. `src/evaluation.ts` — direct/delegated fail-closed decisions and no affiliation transfer;
5. `src/step-up.ts` — human-only exact-scope request/authorization v2 and revalidation;
6. `src/receipts.ts` — complete receipt v2 binding, HMAC, revalidation, and replay;
7. `src/nonce.ts` — atomic one-time contract.

Use `docs/principal-and-delegation-model.md` as the reviewer map.

## 4. Follow the API and strict SDK

Inspect `apps/core-api/src/app.ts` for separate credential/delegation routes, exact mode schemas, same-request receipt issuance, retained-decision step-up, complete consumption bindings, and current-state onboarding views.

Inspect `packages/sdk/src/validation.ts` before relying on TypeScript types. It validates exact response keys, versions, authority-mode discriminants, field relationships, decision/reason coherence, and onboarding/receipt/authorization shapes at runtime.

## 5. Execute versioned transcripts

`fixtures/full-stack-reference-cases.json` is parsed strictly and executed by:

- `apps/core-api/test/lifecycle-fixtures.test.ts`;
- `packages/sdk/test/lifecycle-fixtures.test.ts`.

The runners execute every transcript operation and reject missing/unknown fixture fields. The fixture is not a narrative claim.

## 6. Inspect both UIs

- `apps/operator-ui` displays principal type, direct/delegated mode, acting credential, effective scope, grantor/delegation binding, step-up, and one-time consumption.
- `apps/zkya-onboarding` displays current credential/delegation status, exact eligibility, human approval state, and receipt lifecycle through retained onboarding views.

Neither UI verifies identity or executes a protected action.

## 7. Verify the real local Chromium path

`npm run test:browser` builds the relevant workspaces, starts the compiled API on an ephemeral IPv4-loopback port, serves the built zkYA UI with same-origin proxying, and drives `e2e/zkya-onboarding.spec.ts`. Confirm that it covers direct consume/replay, delegated scope, human approval/rejection, scope denials, and revoked delegation state through real browser HTTP calls.

## 8. Read evidence and limits

Review:

- `docs/evidence-map.md`;
- `CLAIMS_AND_LIMITATIONS.md`;
- `PROVENANCE.md`;
- `docs/google-deepmind-cv-evidence-addendum-2026-08-09.md`;
- `VERIFICATION_RECEIPT_TEMPLATE.md`.

The candidate is integrated local reference evidence only—not production identity/KYC/AML, ZK verification, authentication, deployment, durable state, protected execution, adoption, external validation, or a public/immutable v0.3 release.
