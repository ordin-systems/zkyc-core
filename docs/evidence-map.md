# Evidence Map

## Candidate identity and authority claims

| Reviewer-facing claim | Implementation artifact | Executable evidence |
|---|---|---|
| Exact `HUMAN` / `ORGANIZATION` / `AGENT` principals | `src/domain.ts`, `src/credentials.ts` | Core principal/credential v2 tests; API/SDK strict-schema tests |
| Credential v2 exact capabilities/actions/resources and scope hash | `src/credentials.ts` | Core scope, redirect, tamper, and revocation tests |
| Explicit direct/delegated modes with no mixed fields | `src/evaluation.ts` | Core and API fail-closed mode tests |
| Separate delegate identity and grantor credentials | `src/evaluation.ts`, `src/delegations.ts` | Core self-delegation and same-credential rejection; substitution/inactivity tests; delegated API/SDK lifecycle tests |
| One-hop attenuation and no delegated redelegation | `src/delegations.ts` | Core delegation issuance/scope-escalation tests |
| No grantor-affiliation transfer | `src/evaluation.ts` | Core delegated-affiliation test; operator/zkYA UI tests |
| Immutable trusted-policy registry, policy-pinned delegation, and binding hash | `src/policy.ts`, `src/credentials.ts`, `src/evaluation.ts`, `src/delegations.ts` | Core registry replacement, untrusted-policy, exact-version, and binding-tamper tests |
| Delegation expiry/revocation enforcement | `src/delegations.ts`, `src/evaluation.ts` | Core, API, transcript, and Chromium revoked/expired paths |
| Human-only exact-scope step-up | `src/step-up.ts` | Core human/type/capability/action/resource and fabricated-decision tests; API/SDK/UI paths |
| Step-up v2 preserves direct/delegated authority | `src/step-up.ts` | Core redirect/revalidation/replay tests; API/SDK lifecycle tests |
| Authority-bound HMAC receipt v2 | `src/receipts.ts` | Core binding/tamper/expiry/revalidation tests; API/SDK tests |
| Sequential/concurrent one-time consumption | `src/nonce.ts`, `src/receipts.ts`, `src/step-up.ts` | Core replay/concurrency/storage-failure tests |
| Context metadata cannot grant authority | `src/domain.ts`, `src/evaluation.ts` | Core `zkPassProofId` test |

## Full-stack candidate claims

| Reviewer-facing claim | Implementation artifact | Executable evidence |
|---|---|---|
| Strict Hono issuance/evaluation/delegation/consumption routes | `apps/core-api/src/app.ts` | 13 API/server tests |
| Receipts only from same-request `ALLOW`; step-up only from retained decision | `apps/core-api/src/app.ts` | API provenance and injection tests |
| Retained current-state zkYA onboarding views | `apps/core-api/src/app.ts` | API onboarding lifecycle tests; SDK/UI/Chromium paths |
| Strict runtime-validated, request-correlated browser SDK | `packages/sdk/src/index.ts`, `packages/sdk/src/validation.ts` | 12 SDK tests, including credentialless-denial and step-up decision-log correlation |
| Versioned transcripts execute through API and SDK | `fixtures/full-stack-reference-cases.json` | API and SDK transcript runners |
| Operator authority cockpit | `apps/operator-ui/src/App.tsx` | 3 operator UI tests and workspace build/typecheck checks |
| Dedicated zkYA onboarding UI | `apps/zkya-onboarding/src/App.tsx` | 9 zkYA component tests and workspace build/typecheck checks |
| Real local browser SDK/HTTP stack | `scripts/full-stack-smoke.mjs`, `e2e/zkya-onboarding.spec.ts`, `playwright.config.ts` | 1 Chromium E2E test |
| Fail-closed recursive publication/archive scanner | `scripts/security-check.mjs`, `scripts/archive-utils.mjs`, `scripts/security-check.test.mjs` | 9 scanner regressions, including nested archives and shared limits |
| Loopback-only compiled listener | `apps/core-api/src/server-runtime.ts` | API/server socket test |
| Source-derived package/archive and dependency gates | `scripts/package-check.mjs`, `scripts/package-utils.mjs`, `scripts/package-check.test.mjs`, `package-lock.json`, `package.json` | 7 release-tooling regression tests; `npm run package:check`; `npm audit --audit-level=high` |

## Exact behavioral inventory

- core: 46 tests;
- API/server: 13 tests;
- SDK: 12 tests;
- operator UI: 3 tests;
- zkYA component: 9 tests;
- scanner regression: 9 tests;
- release-tooling regression: 7 tests;
- Chromium E2E: 1 test.

Format, security, typecheck, build, package, and dependency-audit results are separate checks. The checked-in CI workflow is inspectable configuration; this candidate documentation does not claim CI is green for the current head.

## Provenance and dated evidence

| Claim | Artifact | Boundary |
|---|---|---|
| Joint authorship/co-architecture | `AUTHORS.md`, `PROVENANCE.md` | No responsibility split |
| Historical release lineage | `PROVENANCE.md`, historical release notes | v0.2.1 remains unchanged |
| Post-CV candidate reconciliation | `docs/google-deepmind-cv-evidence-addendum-2026-08-09.md` | Not deadline-time or release evidence |
| Later exact-tag verification | `VERIFICATION_RECEIPT_TEMPLATE.md` | Template only; no publication/readback proof |

## Maturity boundary

This is an integrated local reference candidate, not production identity/KYC/AML, ZK verification, authentication, deployment, durable/distributed state, protected execution, adoption, independent review, or external validation. It is not a published or immutable v0.3 release.
