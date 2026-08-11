# Reviewer Walkthrough

This walkthrough reviews the integrated local `v0.3.1` corrective candidate. Historical immutable `v0.3.0` is already published; this successor does not yet claim merge, protected current-head CI, tag, release, archive, clean-room replay, or public readback.

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

Expected for the exact `v0.3.1` candidate checkout:

- core 46;
- API/server 13;
- SDK 223;
- operator UI 3;
- zkYA component 9;
- scanner regression 9;
- release-tooling regression 8;
- Chromium E2E 1.

Bind these results to the exact commit/tree in the later verification receipt; this checked-in walkthrough does not self-attest its containing commit.

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

Inspect `apps/core-api/src/app.ts` for separate credential/delegation routes, exact request schemas, same-request receipt issuance, retained-decision step-up, complete consumption bindings, and current-state onboarding views.

Trace all five decision variants through `packages/sdk/src/index.ts` and `packages/sdk/src/validation.ts`: unbound direct, bound direct, unbound delegated, acting-only delegated, and fully bound delegated. Confirm that reason codes are legal only at their reachable binding stage, partial delegated binding sets are rejected, and every negative/partial response is receipt-free.

Review the dual `DELEGATION_IDENTITIES_NOT_DISTINCT` transport separately:

- `POST /delegations` issuance: exact HTTP `400` domain-error envelope;
- `POST /evaluations`: HTTP `200` acting-only delegated denial.

Follow request-correlation helpers for typed identity/affiliations, action, resource, context, policy, hashes, time, scope, delegation identities, and attenuation. The SDK rejects contradictions in these request-observable facts. It permits coarse unbound `DELEGATION_GRANTOR_CREDENTIAL_INVALID` for cross-authority/core contexts while public Hono normally uses the fully bound form; neither is independent proof of server-authoritative private registration or revocation state.

## 5. Inspect monotonic receipt projection

The onboarding projection has two independent axes:

- durable `consumptionStatus`: `NOT_ISSUED`, `UNCONSUMED`, or `CONSUMED`;
- `lastAttempt`: `NONE`, `ACCEPTED / RECEIPT_VALID`, or `REJECTED` with an associated non-malformed failure reason.

Follow the real-Hono and SDK lifecycle tests through rejection, successful consumption, and replay. Confirm that replay leaves durable status `CONSUMED` while the latest attempt becomes `REJECTED / RECEIPT_REPLAYED`, and that malformed or unassociated input leaves projection state unchanged.

## 6. Execute versioned transcripts

`fixtures/full-stack-reference-cases.json` is parsed strictly and executed by:

- `apps/core-api/test/lifecycle-fixtures.test.ts`;
- `packages/sdk/test/lifecycle-fixtures.test.ts`.

The runners execute every transcript operation and reject missing, unknown, contradictory, or impossible fixture fields. The fixture is not a narrative claim.

## 7. Inspect both UIs

- `apps/operator-ui` displays principal type, direct/delegated mode, acting credential, effective scope, grantor/delegation binding, step-up, and one-time consumption.
- `apps/zkya-onboarding` displays current credential/delegation status, exact eligibility, human approval state, durable receipt consumption, and latest attempt separately.

Neither UI verifies identity or executes a protected action.

## 8. Verify the real local Chromium path

`npm run test:browser` builds the relevant workspaces, starts the compiled API on an ephemeral IPv4-loopback port, serves the built zkYA UI with same-origin proxying, and drives `e2e/zkya-onboarding.spec.ts`. Confirm that it covers direct consume/replay, delegated scope, human approval/rejection, scope denials, and revoked delegation state through real browser HTTP calls.

## 9. Read provenance, evidence, and limits

Review:

- `docs/evidence-map.md`;
- `CLAIMS_AND_LIMITATIONS.md`;
- `PROVENANCE.md`;
- `release-notes-v0.3.0.md`;
- `release-notes-v0.3.1.md`;
- `docs/google-deepmind-cv-evidence-addendum-2026-08-09.md`;
- `VERIFICATION_RECEIPT_TEMPLATE.md`.

Automated AI assistants supported implementation and separate off-GitHub specification/code-quality review contexts. Those tools are not authors or external auditors. Canonical project credit remains Mike “Mizzy” Barrera and Monique Abrams — joint authors and co-architects.

The candidate is integrated local reference evidence only—not production identity/KYC/AML, ZK verification, authentication, deployment, durable state, protected execution, adoption, or external validation. `v0.3.0` is historical and immutable; `v0.3.1` is not yet a published release.
