# Threat Model

## Protected properties

- principal ID and exact `HUMAN` / `ORGANIZATION` / `AGENT` type stay bound to authority artifacts;
- callers cannot mix direct and delegated input lanes;
- delegated authority uses separate acting and grantor credentials;
- delegation cannot widen grantor capability/action/resource scope or confer redelegation;
- grantor affiliations do not transfer to a delegate;
- delegation remains pinned to exact policy content and validity;
- only an exact-scope active `HUMAN` credential can approve step-up;
- receipt/authorization v2 cannot be redirected across authority, action, resource, context, policy, or decision bindings;
- expired or revoked acting/grantor/delegation/approver authority fails closed at later transitions;
- a valid authorization nonce is consumed at most once;
- contextual proof identifiers cannot grant authority.

## Adversarial cases covered

- missing, malformed, unknown, expired, revoked, substituted, or type-mismatched credentials;
- mixed authority modes and unknown fields;
- delegation forgery, binding tamper, scope escalation, redelegation attempt, policy mismatch, expiry, revocation, and substitution;
- credential, delegation, capability, action, resource, affiliation, sensitivity, and policy mismatch;
- non-human, wrong-capability, wrong-action, wrong-resource, duplicate, rejected, expired, or pre-request step-up resolution;
- step-up and receipt authority-field redirect attempts;
- HMAC field/signature tamper, wrong key, expiry, non-authorizing receipt, and incoherent decision/reason;
- sequential and concurrent replay, nonce-domain collision attempts, and storage errors;
- malformed API media/schema/prototype-control input and malformed SDK success/error responses;
- stale retained onboarding status after revocation or expiry;
- real-browser direct/delegated/step-up/denial/replay paths over local HTTP.

## Trust assumptions

- the HMAC key is secret and at least 32 bytes;
- injected clocks and configured credential/delegation authorities are trustworthy;
- trusted issuer-side callers preserve evaluator provenance when bypassing the Hono adapter;
- the pinned policy and registered in-memory artifacts are authoritative for this process;
- a production nonce adapter would implement durable atomic compare-and-set semantics;
- a downstream adapter would verify and consume authority immediately before action handoff.

## Deliberately absent controls

- HTTP authentication, tenant isolation, authenticated administration, rate limits, and deployment hardening;
- durable/distributed storage, consensus, disaster recovery, and cross-process replay coordination;
- real identity proofing, KYC/AML, and zero-knowledge-proof verification;
- asymmetric/public credentials or receipts;
- protected-action execution, payment/custody, and webhooks;
- production monitoring, adoption, and independent external validation.

## Evidence boundary

Tests and Chromium smoke establish bounded local behavior. They do not establish production security, a public/immutable `v0.3.1` successor release, current-head protected CI success, or independent external review. Historical `v0.3.0` publication does not satisfy those successor gates.
