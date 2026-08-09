# Changelog

All notable changes to the bounded public reference implementation are recorded here.

## 0.2.1-full-stack-reference — 2026-08-09

### Corrected

- credited Mike “Mizzy” Barrera and Monique Abrams together as joint authors and co-architects;
- removed separate responsibility labels from project-level authorship credit;
- updated patch-release metadata without changing runtime behavior or trust boundaries.

### Lineage

- `v0.2.0-full-stack-reference` and `v0.1.0-reference` remain immutable and unchanged.

## 0.2.0-full-stack-reference — 2026-08-09

### Added

- sanitized Hono reference API around the deterministic core;
- retained evaluator-result provenance for receipt issuance and step-up creation;
- credential, evaluation, step-up, receipt-consumption and decision-log routes;
- browser-compatible typed TypeScript SDK and contract tests;
- React/Vite reviewer cockpit for `ALLOW`, `DENY`, `STEP_UP`, approval/rejection and one-time consumption;
- automated Vitest/jsdom cockpit interactions covering approval, rejection, consumption and replay rejection;
- deterministic full-stack fixtures;
- API adversarial tests for malformed input, unknown fields, decision injection, prototype-control fields, receipt tampering, redirect mismatch and replay;
- workspace-wide format/security scans, strict typechecks, tests and CI-backed builds.

### Corrected

- canonical JSON normalization now uses a null-prototype accumulator so an own `__proto__` property is preserved as data rather than colliding with an empty object;
- added core and API regressions proving distinct canonical context hashes.

### Boundaries

- all API state and reason-coded logs remain in memory;
- network authentication, tenancy, rate limiting and production storage are intentionally absent;
- the UI cannot execute protected actions;
- the project remains `UNLICENSED` / all rights reserved.

## 0.1.0-reference — 2026-08-08

### Added

- deterministic principal, credential, capability, permission and action-policy model;
- credential issuance, expiry and revocation handling;
- reason-coded `ALLOW`, `DENY` and `STEP_UP` outcomes;
- time-bounded human step-up lifecycle;
- canonical HMAC-SHA256 receipts with timing-safe verification;
- atomic one-time nonce-store contract and in-memory reference adapter;
- negative-path and concurrency tests, deterministic fixtures and clean verification commands;
- architecture, threat-model, provenance, authorship, limitations and reproducibility documentation;
- GitHub Actions verification across supported Node versions.

The immutable v0.1 release remains available as originally published. v0.2 is a successor release and does not rewrite it.
