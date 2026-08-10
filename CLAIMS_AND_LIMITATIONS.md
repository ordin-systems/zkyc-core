# Claims and Limitations

## Supported v0.3 candidate claims

At executable baseline `55d15981cf7f45e441205eb96f5aae79e58d00ae`, the integrated local reference candidate supports these bounded claims:

- exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types;
- credential v2 binding of principal ID/type, credential-bound affiliations, capabilities, exact actions, exact resources, issuer, validity, and scope hash;
- explicit `DIRECT` and `DELEGATED` authority modes;
- registered one-hop delegations that bind distinct grantor and delegate identities, the grantor credential, exact policy ID/version, time bounds, and attenuated capability/action/resource scope;
- separate, non-reusable delegate identity and grantor credentials, without transfer of grantor affiliations or delegated `delegation:issue` authority;
- immutable startup policy registries with exact `(id, version)` resolution and live policy outcome re-evaluation at authorizing transitions;
- deterministic, reason-coded `ALLOW`, `DENY`, and `STEP_UP` decisions;
- current credential, grantor credential, delegation, policy, expiry, and revocation checks where applicable;
- human-only step-up approval/rejection with the required capability and exact `step-up:resolve` action/resource scope;
- authority-bound step-up request/authorization v2 with transition and consumption revalidation;
- HMAC-SHA256 receipt v2 bound to mode, typed subject, acting credential, effective scope, action/resource/context, policy, outcome/reason, and delegated grant fields when applicable;
- timing-safe verification and atomic one-time receipt/authorization consumption;
- Hono reference API with retained evaluator provenance and current-state onboarding projections;
- browser-compatible TypeScript SDK with strict exact-schema runtime validation and request/response authority correlation;
- operator and zkYA React/Vite reference UIs;
- deterministic core fixtures plus versioned full-stack transcripts executed by API and SDK tests;
- a real local Chromium test through the built zkYA UI, SDK, and loopback API;
- fail-closed recursive publication/archive scanning, strict tar-padding validation, and source-derived package allowlists exercised through blank-consumer imports and an installed API probe.

Current behavioral counts are core 46, API/server 13, SDK 12, operator UI 3, zkYA component 9, scanner regression 9, release-tooling regression 7, and Chromium E2E 1. Typechecks, builds, formatting, security scanning, package verification, and dependency audit are checks rather than tests.

## Non-claims

This candidate does not establish:

- production identity proofing, KYC/AML, or zero-knowledge-proof verification;
- production authentication, authorization administration, tenancy, rate limiting, deployment security, monitoring, or operational readiness;
- durable/distributed credential, delegation, decision, step-up, onboarding, or replay state;
- arbitrary, transitive, or redelegable authority;
- transfer of a grantor's affiliations to a delegate;
- asymmetric/public attestation, independently portable credentials, or independent receipt verification outside the shared-secret trust domain;
- separation of duties or a blanket self-approval prohibition beyond the exact human/type/capability/action/resource checks implemented;
- protected-action execution, payment/x402 behavior, custody, or webhooks;
- customers, adoption, scale, production use, independent review, or external validation;
- publication, merge, tag, immutable v0.3 release, public v0.3 URL, archive digest, logged-out readback, or npm registry package.

## Adapter and evidence boundary

The Hono adapter issues receipts only in the evaluation transaction that produced the matching `ALLOW`, retains evaluator results server-side, creates step-up requests from retained decision-log IDs, and requires complete authority bindings at consumption. It is nevertheless unauthenticated and in-memory and must not be deployed as-is.

The candidate source and tests are post-CV evidence. They do not retroactively change what existed at the frozen CV date or at historical `v0.2.1-full-stack-reference`.

`zkPassProofId` and similar identifiers remain contextual metadata only.
