# Architecture

## Authority boundary

zKYC Core is a deterministic authority-decision and one-time-consumption reference. It does not execute the requested action.

```text
Typed principal + acting identity credential
        +
DIRECT credential
   or
DELEGATED grantor credential + one-hop delegation
        +
Exact action/resource/context + versioned policy
        ↓
Deterministic evaluator
        ↓
ALLOW | DENY | STEP_UP + reason + trusted binding stage
        │
        ├─ unbound direct/delegated denial
        ├─ acting-only delegated denial
        └─ bound direct or fully bound delegated decision
                  │
                  ├─ fully bound ALLOW → trusted adapter issues receipt v2
                  │                      → current authority revalidated
                  │                      → receipt nonce consumed once
                  │
                  └─ fully bound STEP_UP → retained request v2
                                         → exact-scope HUMAN resolves
                                         → current authority revalidated
                                         → authorization v2 consumed once
```

Negative, unbound, and partially bound results never receive receipts. Decision fields reflect only the authority stage core actually trusted; the adapter and SDK do not fill missing authority fields from caller artifacts.

## Components

1. **Domain model** — exact `HUMAN`, `ORGANIZATION`, and `AGENT` principals plus validated identifiers, affiliations, sensitivity, and reason codes.
2. **Credential authority** — registered credential v2 issuance, exact scope hashing, status lookup, expiry, and revocation.
3. **Delegation authority** — registered policy-pinned one-hop grants with scope attenuation, binding hash, validity, and revocation.
4. **Policy evaluator** — fail-closed direct/delegated evaluation against exact policy content.
5. **Step-up service** — retained, time-bounded human-only resolution and one-time authorization v2.
6. **Receipt service** — canonical authority-bound payload v2, HMAC-SHA256 signing, timing-safe verification, revalidation, and consumption.
7. **Atomic nonce store** — domain-separated one-time consumption contract; the included adapter is in-memory.
8. **Hono trusted adapter** — strict JSON routes, retained evaluator provenance, current onboarding views, and loopback runtime.
9. **TypeScript SDK** — browser-compatible transport with exact runtime validation of unbound direct, unbound delegated, acting-only delegated, bound direct, and fully bound delegated outcomes.
10. **React/Vite interfaces** — the operator authority cockpit and dedicated zkYA onboarding reference.
11. **Evidence runners** — deterministic versioned transcripts plus real local Chromium smoke through the built stack.

## SDK correlation boundary

The SDK correlates request-observable response facts: mode, typed identity and affiliations, action, resource, context, policy, artifact hashes, time, scope, delegation identities, and attenuation. Contradictions fail as `INVALID_RESPONSE`.

Private credential/delegation registration and revocation are server-authoritative. The SDK permits coarse unbound `DELEGATION_GRANTOR_CREDENTIAL_INVALID` for cross-authority/core contexts while the public Hono path normally emits the fully bound form. Denial-only acceptance of a correctly shaped unknown, revoked, or grantor-invalid reason is not independent proof of private state and cannot widen authority.

## Direct and delegated identity lanes

Direct mode uses one active credential bound to the acting principal. Delegated mode uses the delegate's separate identity credential, the grantor's root credential, and a registered one-hop delegation. Capabilities/actions/resources attenuate from the grantor credential; grantor affiliations do not transfer. Delegated policy affiliation checks come only from the delegate identity credential.

## Trusted-adapter boundary

There is no generic receipt-signing endpoint. The API issues a receipt only from the fully authority-bound `ALLOW` generated in the current evaluation request. Step-up creation accepts a retained decision-log ID instead of a caller-supplied decision object.

These invariants strengthen issuer-side provenance but do not make the unauthenticated adapter production-safe. Core issuer primitives still assume trusted callers when used outside the adapter.

## Retained state and onboarding

Credentials, delegations, revocations, decisions, step-up state, onboarding projections, receipt consumption/attempt state, and nonces are retained in memory. `GET /zkya/onboarding-views/:decisionLogId` recomputes current authority and approval while projecting durable `consumptionStatus` separately from `lastAttempt`.

Durable consumption changes only from `UNCONSUMED` to `CONSUMED`. A later rejected replay stays `CONSUMED` and records `REJECTED / RECEIPT_REPLAYED`; malformed or unassociated input leaves both axes unchanged. Restarting the API clears all retained state.

## Interfaces and browser evidence

Both UIs invoke the same strict SDK/API authority path. `npm run test:browser` starts the compiled loopback API and built zkYA app and drives one Chromium E2E test over real local HTTP. This is local execution evidence, not deployment or public availability.

## Maturity boundary

This is an integrated local `v0.3.1` corrective candidate over historical immutable `v0.3.0`. The successor is not yet merged, tagged, released, or published and does not establish production identity/KYC/AML, ZK verification, authentication, deployment, durability, protected execution, adoption, or external validation. The SDK and UIs cannot widen authority and do not execute downstream actions.
