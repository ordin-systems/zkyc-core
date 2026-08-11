# v0.3.0 Release Notes

**Stage:** published immutable reference release.

**Published:** 2026-08-10.

**Release:** https://github.com/ordin-systems/zkyc-core/releases/tag/v0.3.0

**Commit:** `c67f16c39d67b4c56c88d06c9738d4a164d2a27e`

**Tree:** `e73f3401718d01a7e5bcca1aa84b728e7fa55ccc`

These current-main notes record the publication truth for the immutable historical release. They do not alter the source tree or candidate-era wording preserved inside the `v0.3.0` tag.

## Released capability

- exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types;
- scoped credential v2 with exact action and resource scope;
- explicit direct and one-hop delegated authority modes;
- separate acting-subject identity credential and grantor credential;
- exact credential-bound grantor identity and affiliation matching at delegation issuance;
- stable delegation validation codes preserved through Hono and surfaced by the SDK;
- no grantor-affiliation transfer to the delegate;
- delegation attenuation across capabilities, actions, and resources, with redelegation authority excluded;
- policy ID/version pinning and expiry/revocation revalidation;
- immutable startup policy allowlists with exact live-policy re-evaluation at every authorizing transition;
- human-only step-up with exact approver capability, `step-up:resolve` action, and resource scope;
- authority-bound step-up v2 and HMAC-SHA256 receipt v2 with one-time consumption;
- strict SDK runtime validation and request correlation at the released boundary;
- retained zkYA onboarding views, operator cockpit, and dedicated zkYA UI;
- executable versioned lifecycle transcripts through API and SDK;
- real local Chromium E2E through the built zkYA UI, SDK, and loopback API;
- fail-closed recursive archive scanning, package verification, and blank-consumer package proof.

## Released verification inventory

- 46 core tests;
- 13 API/server tests;
- 12 SDK tests;
- 3 operator UI tests;
- 9 zkYA component tests;
- 9 scanner regression tests;
- 7 release-tooling regression tests;
- 1 Chromium E2E test.

Typecheck, build, format, security, package, and dependency-audit gates were separate checks.

## Forward correction boundary

Exact-source readback after publication found SDK denial-correlation and retained receipt-projection defects that did not establish an authority-widening core bypass. Those defects are corrected only in the forward `v0.3.1` successor. The immutable `v0.3.0` release, tag, commit, tree, assets, and historical claims remain unchanged.

## Compatibility and state

`v0.3.0` is a forward successor to historical `v0.2.1-full-stack-reference`; it does not modify that immutable release. Authority artifacts use v2 bindings, while delegation and onboarding projections have their own versioned schemas. State remains in-memory and resets with the API process.

No npm registry publication is authorized.

## Maturity

This is an integrated local reference release, not production identity/KYC/AML, ZK verification, authentication, deployment, durability, protected execution, adoption, or external validation.
