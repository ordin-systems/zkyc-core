# v0.3.0 Candidate Release Notes

**Stage:** integrated local reference candidate; unreleased.

**Executable baseline:** `1a15de8117ea27672fbd7fffa1c63f633ca3b9bd`.

These notes describe candidate behavior. They are not evidence of a merge, tag, GitHub release, publication, immutable setting, CI result for this head, independent approval, archive digest, logged-out readback, or npm package.

## Candidate capability

- exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types;
- scoped credential v2 with exact action and resource scope;
- explicit direct and one-hop delegated authority modes;
- separate acting-subject identity credential and grantor credential;
- no grantor-affiliation transfer to the delegate;
- delegation attenuation across capabilities, actions, and resources, with redelegation authority excluded;
- policy ID/version pinning and expiry/revocation revalidation;
- human-only step-up with exact approver capability, `step-up:resolve` action, and resource scope;
- authority-bound step-up v2 and HMAC-SHA256 receipt v2 with one-time consumption;
- strict SDK runtime validation of exact route schemas and request/response authority correlation;
- retained zkYA onboarding views showing current authority, eligibility, approval, and receipt state;
- existing operator cockpit plus dedicated zkYA React/Vite onboarding UI;
- executable versioned lifecycle transcripts through API and SDK;
- real local Chromium E2E through the built zkYA UI, SDK, and loopback API;
- fail-closed scanner/archive/package verification and blank-consumer package proof.

## Candidate test inventory

- 45 core tests;
- 13 API/server tests;
- 10 SDK tests;
- 3 operator UI tests;
- 9 zkYA component tests;
- 7 scanner regression tests;
- 6 release-tooling regression tests;
- 1 Chromium E2E test.

Typecheck, build, format, security, package, and dependency-audit gates are separate checks.

## Compatibility and state

The candidate is a forward successor to historical `v0.2.1-full-stack-reference`; it does not modify that immutable release. Authority artifacts move to v2 bindings, while delegation and onboarding projections have their own versioned schemas. State remains in-memory and resets with the API process.

No npm registry publication is authorized.

## Maturity

This is an integrated local reference candidate, not production identity/KYC/AML, ZK verification, authentication, deployment, durability, protected execution, adoption, or external validation.
