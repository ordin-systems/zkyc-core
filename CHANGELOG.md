# Changelog

All notable changes to the bounded reference implementation are recorded here. Candidate entries are not release records.

## 0.3.1 corrective candidate — unreleased

### Corrected

- completed SDK reason-code parity and exact request correlation for direct, partially bound, and fully bound delegated denials without claiming proof of private server state;
- preserved the earlier server-authoritative `DELEGATION_GRANTOR_CREDENTIAL_INVALID` boundary while correlating every later request-observable denial stage;
- required fully bound delegated success and downstream denials to use retained validated delegate, delegation, and grantor snapshots with exact issuer and issuance-attenuation checks;
- separated durable receipt `consumptionStatus` from `lastAttempt`, preserving `CONSUMED` after rejected replay or other later failures;
- prevented malformed or unassociated receipt input from changing retained receipt projection state;
- made SDK receipt-consumption responses discriminated and rejected impossible or legacy projection shapes;
- reconciled current-main publication, provenance, evidence, and version wording while leaving immutable historical release trees unchanged.

### Automated review provenance

Automated AI assistants were used off-GitHub to support implementation and perform separate specification and code-quality review passes. Their outputs informed maintainer decisions and are process provenance only. They are not project authors, owners, external validators, or third-party security auditors, and automated review is not independent external approval. Git history remains the record of individual commit attribution.

Canonical authorship remains:

**Mike “Mizzy” Barrera and Monique Abrams — joint authors and co-architects.**

### Current candidate verification inventory

- core tests: 46;
- API/server tests: 13;
- SDK tests: 223;
- operator UI tests: 3;
- zkYA component tests: 9;
- scanner regression tests: 9;
- release-tooling regression tests: 8;
- Chromium E2E tests: 1.

Format, security, typecheck, build, package, and dependency-audit gates remain distinct checks and are not counted as tests.

### Candidate boundary

This entry describes a local `v0.3.1` corrective candidate. It does not claim merge, protected CI, tag, release, publication, archive digest, clean-room replay, immutable-release state, or logged-out public readback. Those remain release-stage gates.

## 0.3.0 — 2026-08-10

### Published reference release

- added exact `HUMAN`, `ORGANIZATION`, and `AGENT` principal types bound through credential v2, decisions, step-up artifacts, and receipt v2;
- added explicit `DIRECT` and one-hop `DELEGATED` evaluation modes with distinct acting and grantor credentials;
- added policy-pinned attenuated delegations, current authority revalidation, human-only exact-scope step-up, and authority-bound one-time receipts;
- added Hono API, strict browser SDK, operator and zkYA UIs, versioned API/SDK transcripts, and real local Chromium coverage;
- added fail-closed scanner/archive/package verification and blank-consumer package proof.

The immutable release is preserved at commit `c67f16c39d67b4c56c88d06c9738d4a164d2a27e`, tree `e73f3401718d01a7e5bcca1aa84b728e7fa55ccc`, and [`v0.3.0`](https://github.com/ordin-systems/zkyc-core/releases/tag/v0.3.0). Later corrections land only in `v0.3.1` and do not rewrite this release.

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
