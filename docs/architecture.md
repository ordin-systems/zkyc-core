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
ALLOW | DENY | STEP_UP + reason + complete authority bindings
        │
        ├─ ALLOW → trusted adapter issues receipt v2
        │          → consumer supplies complete expected binding
        │          → current authority revalidated
        │          → receipt nonce consumed once
        │
        └─ STEP_UP → retained decision opens request v2
                    → exact-scope HUMAN resolves
                    → current authority revalidated
                    → authorization v2 consumed once
```

## Components

1. **Domain model** — exact `HUMAN`, `ORGANIZATION`, and `AGENT` principals plus validated identifiers, affiliations, sensitivity, and reason codes.
2. **Credential authority** — registered credential v2 issuance, exact scope hashing, status lookup, expiry, and revocation.
3. **Delegation authority** — registered policy-pinned one-hop grants with scope attenuation, binding hash, validity, and revocation.
4. **Policy evaluator** — fail-closed direct/delegated evaluation against exact policy content.
5. **Step-up service** — retained, time-bounded human-only resolution and one-time authorization v2.
6. **Receipt service** — canonical authority-bound payload v2, HMAC-SHA256 signing, timing-safe verification, revalidation, and consumption.
7. **Atomic nonce store** — domain-separated one-time consumption contract; the included adapter is in-memory.
8. **Hono trusted adapter** — strict JSON routes, retained evaluator provenance, current onboarding views, and loopback runtime.
9. **TypeScript SDK** — browser-compatible transport with exact runtime validation of successful/error responses.
10. **React/Vite interfaces** — the operator authority cockpit and dedicated zkYA onboarding reference.
11. **Evidence runners** — deterministic versioned transcripts plus real local Chromium smoke through the built stack.

## Direct and delegated identity lanes

Direct mode uses one active credential bound to the acting principal. Delegated mode uses the delegate's separate identity credential, the grantor's root credential, and a registered one-hop delegation. Capabilities/actions/resources attenuate from the grantor credential; grantor affiliations do not transfer. Delegated policy affiliation checks come only from the delegate identity credential.

## Trusted-adapter boundary

There is no generic receipt-signing endpoint. The API issues a receipt only from the `ALLOW` generated in the current evaluation request. Step-up creation accepts a retained decision-log ID instead of a caller-supplied decision object.

These invariants strengthen issuer-side provenance but do not make the unauthenticated adapter production-safe. Core issuer primitives still assume trusted callers when used outside the adapter.

## Retained state and onboarding

Credentials, delegations, revocations, decisions, step-up state, onboarding projections, receipt status, and nonces are retained in memory. `GET /zkya/onboarding-views/:decisionLogId` recomputes current authority/approval/receipt state from those retained artifacts. Restarting the API clears all state.

## Interfaces and browser evidence

Both UIs invoke the same strict SDK/API authority path. `npm run test:browser` starts the compiled loopback API and built zkYA app and drives one Chromium E2E test over real local HTTP. This is local execution evidence, not deployment or public availability.

## Maturity boundary

The candidate is not production identity/KYC/AML, ZK verification, authentication, deployment, durability, protected execution, adoption, or external validation. The SDK and UIs cannot widen authority and do not execute downstream actions.
