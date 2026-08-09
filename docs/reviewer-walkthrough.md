# Reviewer Walkthrough

This walkthrough verifies the release without requiring a network service, database, external model or secret.

## 1. Reproduce the build

```bash
npm ci
npm run verify
npm run security:check
npm audit --audit-level=high
```

## 2. Inspect the decision boundary

Start with:

- `src/domain.ts` — validated identity, affiliation, sensitivity and reason-code types;
- `src/credentials.ts` — issuance, status and revocation;
- `src/policy.ts` — versioned permission rules;
- `src/evaluation.ts` — deterministic fail-closed decisions;
- `src/step-up.ts` — human review lifecycle;
- `src/receipts.ts` — canonical signing, verification and replay consumption;
- `src/nonce.ts` — atomic one-time store contract and reference adapter.

## 3. Follow the evidence tests

`test/acceptance.test.ts` covers:

- `ALLOW`, `DENY` and `STEP_UP`;
- malformed, expired and revoked credentials;
- capability and credential-bound affiliation enforcement;
- action sensitivity and resource/context bindings;
- authorized, unauthorized, rejected, expired, pre-request and concurrent step-up resolution;
- signed receipt validity, tampering, expiry, mandatory complete-binding redirect rejection and revocation;
- sequential and concurrent replay attempts;
- `zkPassProofId` as unverified context only;
- checked-in fixtures through the public API.

## 4. Read the limitations

Read `CLAIMS_AND_LIMITATIONS.md` before interpreting the results. The release is a local reference implementation and does not claim production deployment, network authentication, distributed durability, external adoption, automatic provenance proof for plain issuer-side objects or zero-knowledge-proof verification.
