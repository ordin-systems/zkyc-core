# Evidence Map

| Reviewer-facing claim | Implementation artifact | Verification evidence |
|---|---|---|
| Validated principal, affiliation and authority types | `src/domain.ts`, `src/credentials.ts` | Acceptance tests 1–4 and 19 |
| Credential-bound affiliations cannot be caller-injected | `src/credentials.ts`, `src/evaluation.ts` | Acceptance tests 2–3 |
| Versioned capability/permission/action-sensitivity policy | `src/policy.ts`, `src/evaluation.ts` | Acceptance tests 1, 5–6 and 20 |
| Concrete resource and canonical action-context binding | `src/evaluation.ts`, `src/canonical.ts` | Acceptance tests 1, 8, 13 and 22 |
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
| Own `__proto__` context keys remain canonical data and cannot collide with `{}` | `src/canonical.ts` | Core test 22; API transport/canonical-context test 12 |
| Hono API with retained evaluator provenance | `apps/core-api/src/app.ts` | API tests 1–13, especially 2 and 11 |
| Receipt issuance exists only inside same-request `ALLOW` evaluation | `apps/core-api/src/app.ts` | API tests 2–4; no generic signing route |
| Step-up creation rejects arbitrary decision injection | `apps/core-api/src/app.ts` | API test 11 |
| Reason-coded defensive-copy decision/receipt history without reusable signature disclosure | `apps/core-api/src/app.ts` | API test 8 |
| Exact JSON media-type handling and cache-disabled API responses | `apps/core-api/src/app.ts` | API test 10 |
| Loopback-only reference listener | `apps/core-api/src/server-runtime.ts` | API test 13 (real socket binding) |
| Browser-compatible typed SDK, exact response validation and transport/error contract | `packages/sdk/src/index.ts`, `packages/sdk/src/validation.ts` | SDK tests 1–8, including per-field malformed credential rejection in test 5 |
| React/Vite reviewer cockpit and authority-state interaction flow | `apps/operator-ui/src/App.tsx`, `apps/operator-ui/src/scenarios.ts` | UI tests 1–2, strict typecheck and production Vite build |
| CI-backed core/API/SDK/UI builds | `package.json`, `.github/workflows/ci.yml` | `npm run verify` on Node 20/22 |
| Reproducible package and CI | `package-lock.json`, `package.json`, `.github/workflows/ci.yml`, `REPRODUCIBILITY.md`, `scripts/package-check.mjs` | `npm ci --ignore-scripts`, `npm run verify`, archive entry-point checks, offline core/API archive install and import, Node 20/22 CI matrix |
| Extensionless publication files remain inside secret/private-path scanning | `scripts/security-check.mjs`, `scripts/security-check.test.mjs` | Security regression test 1 |
| Provenance and stewardship | `PROVENANCE.md`, `AUTHORS.md`, `NOTICE.md` | Repository readback |

## Maturity boundary

This release is a locally and publicly reproducible full-stack reference implementation. It is not a deployment, production-security, adoption, distributed-durability, protected-action-execution or zero-knowledge-proof-verification claim.
