# v0.3.1 Full-Stack Corrective Candidate

## Purpose and stage

The `v0.3.1` candidate makes direct and one-hop delegated authority inspectable from typed input through current-state presentation and one-time consumption. It is an integrated local corrective candidate, not yet a successor release or deployment. Historical immutable `v0.3.0` remains separate and unchanged.

```text
Operator cockpit or zkYA onboarding UI
                 ↓ strict runtime-validated SDK
Hono loopback trusted adapter + retained state
                 ↓
Credential/delegation authorities + deterministic evaluator
                 ↓
ALLOW | DENY | STEP_UP + exact trusted binding stage
                 ↓
receipt or authorization only from fully bound authority
                 ↓
current-authority revalidation + one-time consumption
```

## Hono API — `apps/core-api`

The adapter owns credential and delegation authorities, step-up service, receipt key, atomic nonce store, retained decision/onboarding state, and deterministic injected clock/ID hooks.

It enforces these transport invariants:

- no generic receipt-signing route;
- receipts only from the current request's fully bound exact `ALLOW`;
- no receipt for `DENY`, `STEP_UP`, unbound, or acting-only results;
- step-up request creation only from a retained decision-log ID;
- separate direct and delegated exact request schemas;
- complete v2 expected bindings before consumption;
- `POST /delegations` duplicate identities as an exact HTTP `400` domain-error envelope;
- delegated evaluation duplicate identities as an HTTP `200` acting-only `DENY / DELEGATION_IDENTITIES_NOT_DISTINCT`;
- `no-store` API responses and generic fail-closed unexpected errors.

The compiled listener binds IPv4 loopback. The API remains unauthenticated and in-memory.

## TypeScript SDK — `packages/sdk`

The SDK exposes typed methods for credentials, delegations, evaluation, step-up, receipt consumption, retained onboarding views, and decision log. It runtime-validates exact keys, versions, mode-specific fields, outcome/reason coherence, and all five decision variants: unbound direct, bound direct, unbound delegated, acting-only delegated, and fully bound delegated.

Request-observable facts are correlated against copied, validated supplied artifacts: typed identity and affiliations, mode, action, resource, context, policy, artifact hashes, time, scope, delegation identities, and attenuation. Contradictions become `INVALID_RESPONSE`.

Private registration and revocation remain server-authoritative denial facts. The SDK also permits coarse unbound `DELEGATION_GRANTOR_CREDENTIAL_INVALID` for cross-authority/core contexts, while the public Hono path normally emits the fully bound form. Acceptance of these correctly shaped denial-only results does not claim independent SDK proof of private state and cannot produce a receipt or widen authority. API domain errors, invalid responses, and network failures remain distinct.

## Operator cockpit — `apps/operator-ui`

The cockpit presents direct allow/deny/step-up and delegated allow flows. It exposes exact principal type, authority mode, acting credential, effective scope, grantor/delegation binding, human resolution, receipt or authorization consumption, and defensive-copy in-memory log entries. It has no protected-action control.

## zkYA onboarding — `apps/zkya-onboarding`

The dedicated onboarding UI presents current principal/credential status, direct/delegated authority, exact delegated capabilities/actions/resources, policy/resource eligibility, approval state, durable receipt consumption, and the latest receipt attempt separately. Replay stays visibly consumed while recording `REJECTED / RECEIPT_REPLAYED`; malformed or unassociated input cannot change retained projection.

See `zkya-onboarding-reference.md`.

## Versioned transcripts

`fixtures/full-stack-reference-cases.json` is a strictly parsed versioned transcript set. API and SDK runners execute each operation rather than treating fixture metadata as proof. Covered lanes include direct allow/replay, explicit denial, approval/rejection, expired/revoked credentials, active/expired/revoked delegation, direct/delegated scope mismatch, delegated allow receipt, and missing onboarding view.

## Browser proof path

`npm run test:browser` builds the API, SDK, and zkYA UI; starts the API on an ephemeral loopback port; serves the built UI with same-origin `/api` proxying; and drives one Playwright Chromium E2E test through real local HTTP. It covers receipt consume/replay, delegated scope, human approval/rejection, scope denial, and revoked delegation presentation.

## State, key, and execution boundaries

Restarting the API clears credentials, delegations, decisions, onboarding views, approvals, receipt consumption/attempt projection, and nonces. The server requires a local HMAC key of at least 32 bytes and never returns it. HMAC receipts are shared-secret artifacts, not public asymmetric attestations.

Neither UI verifies real identity nor executes requested actions. This candidate is not production KYC/AML, ZK verification, authentication, deployment, durable state, adoption, or external validation.
