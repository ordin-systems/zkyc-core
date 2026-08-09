# Claims and Limitations

## Supported v0.2 claims

The verified full-stack reference supports these bounded claims:

- deterministic evaluation of principal, credential, capability, permission and action-policy inputs;
- configurable `ROUTINE`, `SENSITIVE` and `CRITICAL` action tiers;
- reason-coded `ALLOW`, `DENY` and `STEP_UP` outcomes;
- credential issuance, expiry and revocation checks;
- human step-up approval, rejection, expiry and one-time consumption;
- HMAC-signed, time-bounded `ALLOW` receipts with complete semantic binding;
- timing-safe signature verification and credential recheck at consumption;
- sequential and concurrent replay resistance through an atomic-store contract;
- Hono reference API with retained evaluator provenance;
- browser-compatible typed TypeScript SDK;
- React/Vite operator interface;
- reason-coded defensive-copy in-memory decision/receipt history without reusable signature disclosure;
- deterministic fixtures, automated core/API/SDK/UI tests and CI-backed core/API/SDK/UI builds.

## Non-claims

This repository does not establish:

- zero-knowledge-proof verification or real-world KYC/AML;
- production deployment, authentication, security or operational readiness;
- external adoption, validation or independent replication;
- durable or distributed credentials, decision logs, step-up state or replay protection;
- authenticated policy administration or an authoritative policy update channel;
- portable independently signed credentials;
- separation of duties or a prohibition on self-approval;
- approver-credential binding/recheck after approval;
- asymmetric or independently public receipt verification;
- payment execution, x402 behavior, custody of funds, webhooks or protected-action execution;
- automatic evaluator provenance for arbitrary plain objects passed directly to core trusted primitives.

## Adapter boundary

The Hono adapter strengthens issuer-side provenance by:

- issuing receipts only inside the transaction that produced the corresponding `ALLOW`;
- retaining evaluator results server-side;
- creating step-up requests by retained decision-log ID rather than accepting decision objects;
- requiring every receipt expected-binding field before consumption.

The network adapter itself has no authentication and must not be deployed as-is.

`zkPassProofId` and similar identifiers remain contextual metadata only.
