# Changelog

All notable changes to the bounded reference implementation are recorded here. Candidate entries are not release records.

## 0.3.0 candidate — unreleased

### Added

- exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types bound through credential v2, decisions, step-up artifacts, and receipt v2;
- explicit `DIRECT` and `DELEGATED` evaluation modes;
- one-hop capability delegations binding grantor, delegate, grantor credential, policy ID/version, validity window, and attenuated capability/action/resource scope;
- separate delegate identity and grantor credentials, with no transfer of grantor affiliations;
- delegation issuance, revocation, evaluation, onboarding, step-up, receipt, and SDK/API contracts;
- policy/expiry/revocation revalidation across delegated evaluation, step-up transitions, receipt consumption, and retained onboarding views;
- human-only step-up resolution requiring the exact approver capability, `step-up:resolve` action scope, and requested resource scope;
- authority-bound receipt v2 and step-up v2 artifacts, including acting/grantor/delegation bindings and one-time consumption;
- strict SDK runtime validation for exact success and error schemas;
- executable versioned full-stack lifecycle transcripts run through both API and SDK;
- a dedicated zkYA onboarding reference UI and retained `/zkya/onboarding-views/:decisionLogId` projection;
- v0.3 authority bindings in the existing operator UI;
- a real local Chromium smoke test through the built zkYA UI, SDK, and loopback HTTP API;
- current retained step-up eligibility derived from live subject, delegation, approver, expiry, revocation, and one-time-consumption state;
- SDK request/response identity and requested-scope correlation;
- clean-build, path-portable, fail-closed scanner/archive/package verification with blank-consumer imports and installed-API probing.

### Verification inventory at executable baseline `1a15de8117ea27672fbd7fffa1c63f633ca3b9bd`

- core tests: 45;
- API/server tests: 13;
- SDK tests: 10;
- operator UI tests: 3;
- zkYA component tests: 9;
- scanner regression tests: 7;
- release-tooling regression tests: 6;
- Chromium E2E tests: 1.

Format, security, typecheck, build, package, and dependency-audit gates remain distinct checks and are not included as tests.

### Candidate boundary

This entry describes an integrated local reference candidate. It does not claim a merge, tag, release, publication, npm package, current-head CI result, immutable v0.3 artifact, independent review, archive hash, or logged-out public readback.

## 0.2.1-full-stack-reference — 2026-08-09

### Corrected

- credited Mike “Mizzy” Barrera and Monique Abrams together as joint authors and co-architects;
- removed separate responsibility labels from project-level authorship credit;
- updated patch-release metadata without changing runtime behavior or trust boundaries.

### Lineage

- historical `v0.2.0-full-stack-reference` and `v0.1.0-reference` remain unchanged.

## 0.2.0-full-stack-reference — 2026-08-09

### Added

- sanitized Hono reference API around the deterministic core;
- retained evaluator-result provenance for receipt issuance and step-up creation;
- credential, evaluation, step-up, receipt-consumption, and decision-log routes;
- browser-compatible typed TypeScript SDK and contract tests;
- React/Vite reviewer cockpit for decision, resolution, and consumption states;
- deterministic full-stack fixtures and adversarial API tests;
- workspace format/security checks, strict typechecks, tests, and builds.

### Boundaries

- API state and reason-coded logs are in memory;
- network authentication, tenancy, rate limiting, production storage, and protected-action execution are absent;
- the project is `UNLICENSED` / all rights reserved.

## 0.1.0-reference — 2026-08-08

### Added

- deterministic principal, credential, capability, permission, and action-policy model;
- credential validity/revocation handling and reason-coded decisions;
- time-bounded human step-up lifecycle;
- canonical HMAC-SHA256 receipts and atomic one-time nonce-store contract;
- deterministic fixtures, verification commands, and architecture/evidence documentation.
