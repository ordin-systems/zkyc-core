# Architecture

## Decision boundary

zKYC Core is a deterministic authority-decision engine. It does not execute the requested action.

```text
Principal + credential-bound affiliation/capabilities
        +
Requested action + sensitivity + resource + context
        +
Versioned policy
        ↓
Deterministic evaluator
        ↓
ALLOW | DENY | STEP_UP + reason codes
        │
        ├─ ALLOW → trusted authority caller signs receipt
        │          → consumer verifies complete expected bindings
        │          → atomically consumes receipt nonce once
        │
        └─ STEP_UP → trusted authority caller creates review request
                    → authorized approver resolves once
                    → consumer verifies complete authorization bindings
                    → atomically consumes authorization once
```

## Components

1. **Domain model** — validated principal, affiliation, capability, credential, action and policy records.
2. **Credential registry** — issuance, status lookup and revocation.
3. **Policy evaluator** — fail-closed deterministic rules; unsupported or contradictory input is denied.
4. **Step-up registry** — time-bounded human review requiring an authorized approver and one final resolution.
5. **Receipt service** — canonical payload serialization, HMAC-SHA256 signing and timing-safe verification.
6. **Atomic nonce store** — one-time authorization consumption contract. The included in-memory adapter is a reference implementation, not a distributed durability claim.

## Trusted-authority boundary

`signReceipt()` and `HumanStepUpService.createRequest()` are issuer-side primitives. Their callers are trusted authority adapters and must supply the corresponding output from `evaluateAccess()`. A structurally valid plain object does not independently prove policy-decision provenance.

The consumer boundary is stricter: `verifyAndConsumeReceipt()` requires a complete expected binding object, rechecks current credential status and consumes a derived nonce key atomically. Human step-up authorizations use the separate `consumeAuthorization()` path and are not converted into receipts in this release.

## Authority hierarchy

Deterministic policy is authoritative. Contextual metadata—including external proof identifiers—may be recorded but cannot independently grant authority. External AI classification, if added by a future adapter, must remain advisory and cannot override the deterministic evaluator.

## Execution boundary

A valid, consumed `ALLOW` receipt or approved step-up authorization can be used by a separate adapter to permit a downstream action. This repository does not include that adapter or claim that already-running external actions can be interrupted.
