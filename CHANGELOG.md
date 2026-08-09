# Changelog

All notable changes to the bounded public reference implementation are recorded here.

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

### Explicitly excluded

- historical demo UI and fixed-user middleware;
- external-LLM policy authority;
- webhooks;
- x402 and real-funds execution;
- zero-knowledge-proof verification;
- claims of production deployment, adoption or independent validation.
