# v0.3.1 Corrective Candidate Release Notes

**Stage:** integrated local corrective candidate; not yet merged, tagged, released, or published.

**Historical base:** immutable [`v0.3.0`](https://github.com/ordin-systems/zkyc-core/releases/tag/v0.3.0) at commit `c67f16c39d67b4c56c88d06c9738d4a164d2a27e` and tree `e73f3401718d01a7e5bcca1aa84b728e7fa55ccc`.

These notes describe current candidate behavior. They are not evidence of protected CI, merge, tag, GitHub release, publication, immutable-release state, archive digest, clean-room replay, or logged-out readback.

## Corrective scope

- complete SDK reason-code parity across legitimate core/API denial shapes;
- exact direct denial correlation using copied validated credential snapshots;
- delegated denial correlation across acting credential, delegation, grantor credential, tuple, request scope, policy, capability, and affiliation stages;
- preserved server-authoritative transport for coarse grantor-credential invalidity without overclaiming private registration or revocation proof;
- required validated grantor/delegation issuer equality and issuance-equivalent observable attenuation before accepting downstream delegated results;
- fail-closed terminal policy-reason correlation with delegation-only capabilities and acting-credential affiliations;
- monotonic receipt projection separating durable `consumptionStatus` from `lastAttempt`;
- rejected replay or later failure cannot make a consumed receipt appear unconsumed;
- malformed or unassociated receipt input cannot mutate retained projection state;
- discriminated SDK receipt-consumption responses and exact rejection of legacy or impossible projection states;
- current-main documentation, provenance, evidence, health response, manifests, and lockfile reconciled to `0.3.1` candidate identity.

## Automated review provenance

Automated AI assistants were used off-GitHub to support implementation and perform separate specification and code-quality review passes. Their outputs informed maintainer decisions and are process provenance only. They are not authors, owners, maintainers, external validators, or third-party security auditors, and automated review is not independent external approval.

Canonical project credit remains:

**Mike “Mizzy” Barrera and Monique Abrams — joint authors and co-architects.**

## Current local verification inventory

- core: 46 tests;
- API/server: 13 tests;
- SDK: 223 tests;
- operator UI: 3 tests;
- zkYA component: 9 tests;
- scanner regression: 9 tests;
- release-tooling regression: 8 tests;
- Chromium E2E: 1 test.

Format, security, core/workspace typechecks, builds, package proof, and dependency audit are separate checks.

## Required release gates still open

- protected pull request and Node 20/22 current-head CI;
- merged-main verification and exact-tree/tag resolution;
- clean-room replay from the exact tagged source;
- release archive, manifest, verification receipt, and checksums;
- immutable successor publication and logged-out post-publication readback.

No npm registry publication is authorized.

## Maturity

This is an integrated local reference candidate, not production identity/KYC/AML, ZK verification, authentication, deployment, durable/distributed state, protected execution, adoption, or external validation.
