# Evidence Map

| Reviewer-facing claim | Implementation artifact | Verification evidence |
|---|---|---|
| Validated principal, affiliation and authority types | `src/domain.ts`, `src/credentials.ts` | Acceptance tests 1–4 and 19 |
| Credential-bound affiliations cannot be caller-injected | `src/credentials.ts`, `src/evaluation.ts` | Acceptance tests 2–3 |
| Versioned capability/permission/action-sensitivity policy | `src/policy.ts`, `src/evaluation.ts` | Acceptance tests 1, 5–6 and 20 |
| Concrete resource and canonical action-context binding | `src/evaluation.ts`, `src/canonical.ts` | Acceptance tests 1, 8 and 13 |
| Credential issuance, expiry and revocation | `src/credentials.ts` | Acceptance tests 4, 11 and 16 |
| Reason-coded `ALLOW`, `DENY` and `STEP_UP` | `src/evaluation.ts`, `src/domain.ts` | Acceptance tests 1, 4–7 and fixture test 21 |
| Human approval, rejection, expiry, no time-travel and terminal-state handling | `src/step-up.ts` | Acceptance tests 7–11 |
| Revocation-aware step-up consumption | `src/step-up.ts`, `src/credentials.ts` | Acceptance test 11 |
| HMAC-SHA256 receipts and timing-safe signature comparison | `src/receipts.ts` | Acceptance tests 12–16 |
| Consumer-required receipt subject/action/sensitivity/resource/context/policy/credential/decision/reason binding | `src/receipts.ts` | Acceptance test 13 through `verifyAndConsumeReceipt()` |
| Decision/reason coherence and non-authorizing receipt rejection | `src/receipts.ts` | Acceptance tests 14–15 |
| Revocation-aware receipt consumption | `src/receipts.ts`, `src/credentials.ts` | Acceptance test 16 |
| Atomic one-time nonce contract | `src/nonce.ts`, `docs/atomic-store-contract.md` | Acceptance tests 7–8 and 17–18 |
| Sequential and concurrent replay rejection | `src/nonce.ts`, `src/receipts.ts` | Acceptance tests 17–18 |
| Issuer-side provenance is an explicit trusted-adapter boundary | `README.md`, `CLAIMS_AND_LIMITATIONS.md`, `docs/architecture.md` | Documentation readback; not claimed as automatic plain-object provenance proof |
| `zkPassProofId` is non-authoritative metadata only | `src/domain.ts`, `CLAIMS_AND_LIMITATIONS.md` | Acceptance test 19 |
| Checked-in deterministic fixtures use the public API | `fixtures/public-api-cases.json`, `src/index.ts` | Acceptance test 21 |
| Reproducible package and CI | `package-lock.json`, `package.json`, `.github/workflows/ci.yml`, `REPRODUCIBILITY.md` | `npm ci --ignore-scripts`, `npm run verify`, Node 20/22 CI matrix |
| Provenance and stewardship | `PROVENANCE.md`, `AUTHORS.md`, `NOTICE.md` | Repository readback |

## Maturity boundary

This release is a locally and publicly reproducible reference implementation. It is not a deployment, production-security, adoption, distributed-durability or zero-knowledge-proof-verification claim.
