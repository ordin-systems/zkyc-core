# v0.3.0 Candidate Release Notes

**Stage:** integrated local reference candidate; unreleased.

**Executable baseline:** `780fe8704f591f6064940d601b095aa13371d96a`.

These notes describe candidate behavior. They are not evidence of a merge, tag, GitHub release, publication, immutable setting, CI result for this head, independent approval, archive digest, logged-out readback, or npm package.

## Candidate capability

- exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types;
- scoped credential v2 with exact action and resource scope;
- explicit direct and one-hop delegated authority modes;
- separate acting-subject identity credential and grantor credential;
- exact credential-bound grantor identity and affiliation matching at delegation issuance;
- no grantor-affiliation transfer to the delegate;
- delegation attenuation across capabilities, actions, and resources, with redelegation authority excluded;
- policy ID/version pinning and expiry/revocation revalidation;
- immutable startup policy allowlists with exact live-policy re-evaluation at every authorizing transition;
- human-only step-up with exact approver capability, `step-up:resolve` action, and resource scope;
- authority-bound step-up v2 and HMAC-SHA256 receipt v2 with one-time consumption;
- strict SDK runtime validation of exact route schemas and recomputed request/response typed-subject affiliations, scope, context, policy, authority satisfaction and decision-time validity, grantor attenuation, outcome, delegation binding, receipt presence/expiry, resolution intent, decision log, and initial-status correlation;
- retained zkYA onboarding views showing current authority, eligibility, approval, and receipt state;
- existing operator cockpit plus dedicated zkYA React/Vite onboarding UI;
- executable versioned lifecycle transcripts through API and SDK;
- real local Chromium E2E through the built zkYA UI, SDK, and loopback API;
- fail-closed recursive nested-archive scanning, strict tar-padding validation, package verification, and blank-consumer package proof.

## Candidate test inventory

- 46 core tests;
- 13 API/server tests;
- 12 SDK tests;
- 3 operator UI tests;
- 9 zkYA component tests;
- 9 scanner regression tests;
- 7 release-tooling regression tests;
- 1 Chromium E2E test.

Typecheck, build, format, security, package, and dependency-audit gates are separate checks.

## Independent review state

The defensive review of superseded candidate `54f2c343729e9137d2cbec3468266531e885373b` returned `REQUEST_CHANGES`. Its two findings were remediated. The parallel specification review timed out without a verdict after reproducing additional forged SDK derived-hash and policy-semantic acceptance; those paths were also remediated. At superseded candidate `5749f77495bb075871fed0e80eff3ca89e2f9d9f`, the defensive reviewer returned `PASS`, while the specification reviewer returned `REQUEST_CHANGES` after proving an unsatisfied-capability forged `ALLOW`. At superseded candidate `db759f18ff727e59e70f472b193d88cd404e61fe`, both reviewers returned `REQUEST_CHANGES` after proving grantor-scope escalation, and the specification reviewer additionally proved direct affiliation substitution. At superseded candidate `ab67604a67263af316a5dd78643435e3045809fb`, the defensive reviewer returned `PASS`, while the specification reviewer found core delegation issuance still accepted substituted grantor affiliations. The executable baseline above closes all reproduced findings by enforcing exact credential-bound grantor identity/affiliations in core, API, and SDK while retaining delegation attenuation invariants. This successor has not yet received new exact-head independent `PASS` verdicts.

## Compatibility and state

The candidate is a forward successor to historical `v0.2.1-full-stack-reference`; it does not modify that immutable release. Authority artifacts move to v2 bindings, while delegation and onboarding projections have their own versioned schemas. State remains in-memory and resets with the API process.

No npm registry publication is authorized.

## Maturity

This is an integrated local reference candidate, not production identity/KYC/AML, ZK verification, authentication, deployment, durability, protected execution, adoption, or external validation.
