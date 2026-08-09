# zKYC Core

**Agent Identity and Action-Authority Decision Infrastructure**

zKYC Core is a bounded TypeScript reference implementation for deterministic agent identity and action-authority decisions. It evaluates a principal, credential and requested action against a versioned policy; returns a reason-coded `ALLOW`, `DENY` or `STEP_UP`; and can issue a signed, one-time authorization receipt.

## What this release proves

- deterministic principal, affiliation, capability and permission evaluation;
- credential issuance, expiry and revocation;
- fail-closed `ALLOW`, `DENY` and `STEP_UP` decisions;
- human approval, rejection and expiry for escalated actions;
- HMAC-SHA256 decision receipts with timing-safe signature verification;
- one-time nonce consumption through an explicit atomic-store contract;
- deterministic fixtures and automated negative-path and concurrency tests.

## Quick verification

```bash
npm ci
npm run format:check
npm run security:check
npm run typecheck
npm test
npm run build
npm run verify
npm audit --audit-level=high
```

## Evidence chain

`trusted authority caller → deterministic evaluator → ALLOW decision → signed receipt → complete binding verification → one-time consumption`

`trusted authority caller → STEP_UP decision → human resolution → complete authorization verification → one-time consumption`

See:

- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/atomic-store-contract.md`
- `docs/evidence-map.md`
- `docs/reviewer-walkthrough.md`
- `REPRODUCIBILITY.md`
- `CLAIMS_AND_LIMITATIONS.md`
- `PROVENANCE.md`
- `AUTHORS.md`

## Important boundaries

This is a **reference implementation**, not evidence of production deployment, adoption or external validation. The included store is an in-memory reference adapter; production persistence must provide the same atomic consume contract. `signReceipt()` and `HumanStepUpService.createRequest()` are trusted issuer-side primitives: callers must supply corresponding evaluator output, and a structurally valid plain object does not independently prove policy-decision provenance. Receipt consumers must provide complete expected bindings. This release does not include the historical demo UI, fixed-user middleware, webhooks, external-LLM policy authority, x402 or real-funds execution.

A `zkPassProofId` or similar proof identifier may be preserved as contextual metadata. zKYC Core does **not** verify a zero-knowledge proof.

No license is granted unless and until ORDIN publishes an explicit license file.
