# Technical Evidence Index and Map

## Candidate identity and authority claims

| Reviewer-facing claim | Implementation artifact | Executable evidence |
|---|---|---|
| Exact `HUMAN` / `ORGANIZATION` / `AGENT` principals | `src/domain.ts`, `src/credentials.ts` | Core principal/credential v2 tests; API/SDK strict-schema tests |
| Credential v2 exact capabilities/actions/resources and scope hash | `src/credentials.ts` | Core scope, redirect, tamper, and revocation tests |
| Explicit direct/delegated modes with no mixed fields | `src/evaluation.ts` | Core and API fail-closed mode tests |
| Exact credential-bound grantor affiliations plus separate delegate/grantor credentials | `src/evaluation.ts`, `src/delegations.ts` | Core affiliation/self-delegation/same-credential rejection; substitution/inactivity tests; delegated API/SDK lifecycle tests |
| One-hop attenuation and no delegated redelegation | `src/delegations.ts` | Core delegation issuance/scope-escalation tests; SDK impossible-issuance correlation regressions |
| No grantor-affiliation transfer | `src/evaluation.ts` | Core delegated-affiliation test; operator/zkYA UI tests |
| Immutable trusted-policy registry, policy-pinned delegation, and binding hash | `src/policy.ts`, `src/credentials.ts`, `src/evaluation.ts`, `src/delegations.ts` | Core registry replacement, untrusted-policy, exact-version, and binding-tamper tests |
| Delegation expiry/revocation enforcement | `src/delegations.ts`, `src/evaluation.ts` | Core, API, transcript, and Chromium revoked/expired paths |
| Human-only exact-scope step-up | `src/step-up.ts` | Core human/type/capability/action/resource and fabricated-decision tests; API/SDK/UI paths |
| Step-up v2 preserves direct/delegated authority | `src/step-up.ts` | Core redirect/revalidation/replay tests; API/SDK lifecycle tests |
| Authority-bound HMAC receipt v2 | `src/receipts.ts` | Core binding/tamper/expiry/revalidation tests; API/SDK tests |
| Sequential/concurrent one-time consumption | `src/nonce.ts`, `src/receipts.ts`, `src/step-up.ts` | Core replay/concurrency/storage-failure tests |
| Context metadata cannot grant authority | `src/domain.ts`, `src/evaluation.ts` | Core `zkPassProofId` test |

## Full-stack `v0.3.1` candidate claims

| Reviewer-facing claim | Implementation artifact | Executable evidence |
|---|---|---|
| Strict Hono issuance/evaluation/delegation/consumption routes with stable delegation domain codes | `apps/core-api/src/app.ts` | 13 API/server tests, including exact grantor-mismatch code preservation |
| Exact decision binding stages | `src/evaluation.ts`, `apps/core-api/src/app.ts`, `packages/sdk/src/validation.ts` | Real-Hono and SDK tests for unbound direct, unbound delegated, acting-only delegated, bound direct, and fully bound delegated outcomes |
| Complete SDK reason parity | `src/domain.ts`, `packages/sdk/src/index.ts`, `packages/sdk/src/validation.ts` | Compile-time core/SDK equality plus runtime coverage of every core reason and unknown-code rejection |
| Dual duplicate-identity transport | `apps/core-api/src/app.ts`, `packages/sdk/src/index.ts` | Issuance HTTP `400` exact `DELEGATION_IDENTITIES_NOT_DISTINCT` envelope; evaluation HTTP `200` acting-only denial |
| Request-observable denial correlation | `packages/sdk/src/index.ts`, `packages/sdk/src/integrity.ts`, `packages/sdk/src/validation.ts` | Direct/delegated mutation probes across identity, affiliation, action, resource, context, policy, scope, time, delegation identity/binding, attenuation, and outcome |
| Server-authoritative denial boundary | `packages/sdk/src/index.ts`, `packages/sdk/src/validation.ts` | Legal `UNKNOWN`, `REVOKED`, and coarse unbound `DELEGATION_GRANTOR_CREDENTIAL_INVALID` acceptance; public Hono normally uses the fully bound grantor-invalid shape; neither proves private state or widens authority |
| Terminal policy correlation | `packages/sdk/src/index.ts` | SDK regressions for rule, sensitivity, deny effect, delegation-only capability, acting affiliation, approver omission, metadata, and receipt absence |
| Receipts only from same-request `ALLOW`; step-up only from retained decision | `apps/core-api/src/app.ts` | API provenance and injection tests |
| Monotonic retained receipt projection | `apps/core-api/src/app.ts` | API and SDK reject/consume/replay/malformed/unassociated lifecycle tests; UI/Chromium replay path |
| Retained current-state zkYA onboarding views | `apps/core-api/src/app.ts` | API onboarding lifecycle tests; SDK/UI/Chromium paths |
| Strict runtime-validated, request-correlated browser SDK | `packages/sdk/src/index.ts`, `packages/sdk/src/validation.ts`, `packages/sdk/src/integrity.ts` | 223 SDK tests covering direct/delegated success, partial/full denial correlation, request-observable attenuation, receipt projection, and forged-response rejection |
| Versioned transcripts execute through API and SDK | `fixtures/full-stack-reference-cases.json` | API and SDK transcript runners |
| Operator authority cockpit | `apps/operator-ui/src/App.tsx` | 3 operator UI tests and workspace build/typecheck checks |
| Dedicated zkYA onboarding UI | `apps/zkya-onboarding/src/App.tsx` | 9 zkYA component tests and workspace build/typecheck checks |
| Real local browser SDK/HTTP stack | `scripts/full-stack-smoke.mjs`, `e2e/zkya-onboarding.spec.ts`, `playwright.config.ts` | 1 Chromium E2E test |
| Fail-closed recursive publication/archive scanner | `scripts/security-check.mjs`, `scripts/archive-utils.mjs`, `scripts/security-check.test.mjs` | 9 scanner regressions, including nested archives and shared limits |
| Loopback-only compiled listener | `apps/core-api/src/server-runtime.ts` | API/server socket test |
| Source-derived package/archive, version-alignment, and dependency gates | `scripts/package-check.mjs`, `scripts/package-utils.mjs`, `scripts/package-check.test.mjs`, `package-lock.json`, `package.json` | 8 release-tooling regression tests; `npm run package:check`; `npm audit --audit-level=high` |

## Exact behavioral inventory

- core: 46 tests;
- API/server: 13 tests;
- SDK: 223 tests;
- operator UI: 3 tests;
- zkYA component: 9 tests;
- scanner regression: 9 tests;
- release-tooling regression: 8 tests;
- Chromium E2E: 1 test.

Format, security, typecheck, build, package, and dependency-audit results are separate checks. The checked-in CI workflow is inspectable configuration; current-head protected CI remains a release-stage gate.

## Provenance and dated evidence

| Claim | Artifact | Boundary |
|---|---|---|
| Joint authorship/co-architecture | `AUTHORS.md`, `PROVENANCE.md` | No responsibility split |
| Automated implementation/review assistance | `PROVENANCE.md`, `CHANGELOG.md` | Separate off-GitHub contexts; not authorship, external validation, or third-party audit |
| Historical immutable release lineage | `PROVENANCE.md`, `release-notes-v0.3.0.md` | `v0.3.0` and earlier releases remain unchanged |
| Post-CV dated reconciliation | `docs/google-deepmind-cv-evidence-addendum-2026-08-09.md` | Not deadline-time evidence |
| Current forward correction | `release-notes-v0.3.1.md`, this map | Local candidate until protected release gates pass |
| Later exact-tag verification | `VERIFICATION_RECEIPT_TEMPLATE.md` | Template only; no `v0.3.1` publication/readback proof yet |

## Maturity boundary

This is an integrated local `v0.3.1` corrective candidate, not production identity/KYC/AML, ZK verification, authentication, deployment, durable/distributed state, protected execution, adoption, or external validation. Historical `v0.3.0` is published and immutable; `v0.3.1` is not yet a published release.
