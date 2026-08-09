# Threat Model

## Protected properties

- only authorized principals receive `ALLOW`;
- expired or revoked credentials fail closed;
- escalated decisions require an authorized, timely human resolution;
- receipts cannot be modified without detection;
- a valid authorization nonce is consumed at most once;
- receipt consumption requires complete subject, action, sensitivity, resource, context, policy, credential, decision and reason bindings;
- contextual proof identifiers cannot be mistaken for verified cryptographic proofs.

## Adversarial cases covered by tests

- missing, malformed, expired and revoked credentials;
- insufficient or conflicting capabilities;
- unknown actions and contradictory input;
- unauthorized, duplicate, rejected, expired and pre-request step-up resolution;
- receipt field and signature tampering;
- expiration and binding mismatch;
- sequential and concurrent replay attempts.

## Trust assumptions

- the signing key remains secret and sufficiently strong;
- the injected clock is trustworthy;
- the policy and credential stores are authoritative;
- issuer-side callers of `signReceipt()` and `createRequest()` are trusted authority adapters and pass the corresponding evaluator output;
- a production nonce-store adapter implements atomic compare-and-set semantics durably;
- downstream adapters verify and consume authorization before action handoff.

## Out of scope

- HTTP/API authentication and multitenancy;
- distributed storage, consensus or disaster recovery;
- zero-knowledge-proof verification;
- payment execution or custody;
- external model safety;
- production monitoring, rate limits and deployment security.
