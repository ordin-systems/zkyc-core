# Decision Lifecycle

## 1. Validate typed input

The evaluator validates exact principal type/identity/affiliations, authority mode, credentials, delegation when present, action, resource, canonical context, content-versioned policy, and evaluation time. Unknown fields, mixed direct/delegated fields, malformed identifiers, contradictory rules, and stale policy content fail closed.

A required request field can still carry a malformed or unregistered authority artifact. That produces a reason-coded denial at the binding stage core actually reached; it does not authorize the SDK or adapter to echo untrusted fields into the decision.

## 2. Establish acting authority

### Direct mode

The registered active credential must match the subject ID, type, and affiliations and contain the exact action and resource.

### Delegated mode

The evaluator separately verifies:

- the delegate identity credential matches the acting subject tuple and affiliations;
- the grantor credential matches the delegation's grantor tuple and remains active;
- the registered one-hop delegation matches the delegate/grantor, binding hash, exact policy, time, and revocation state;
- delegated capability/action/resource scope is attenuated and covers the request.

Grantor affiliations are not copied to the delegate or used to satisfy delegated affiliation requirements.

## 3. Preserve exact binding stages

Decision v2 has five reachable authority shapes:

1. **Unbound direct denial** — common decision facts only for missing, malformed, or unknown direct credential.
2. **Bound direct decision** — trusted acting credential/effective scope plus matching direct credential ID.
3. **Unbound delegated denial** — common facts only for missing, malformed, or unknown delegate identity credential; the SDK also permits coarse server-authoritative `DELEGATION_GRANTOR_CREDENTIAL_INVALID` unbound with no independent proof of private state.
4. **Acting-only delegated denial** — trusted delegate identity/effective scope, but no grantor/delegation fields.
5. **Fully bound delegated decision** — trusted delegate, grantor credential, and delegation binding.

The SDK rejects invented bindings, partial delegated binding sets, direct decisions containing delegated fields, and reasons appearing at an impossible binding stage.

Request-observable facts are correlated exactly: typed identity and affiliations, mode, action, resource, context, policy, hashes, time, scope, delegation identities, and attenuation. Registration and revocation remain server-authoritative denial facts; accepting a correctly shaped unknown/revoked denial does not prove private state or widen authority.

## 4. Evaluate exact policy and correlate outcome

The content-derived policy version is recomputed. The exact action rule checks sensitivity, required capabilities, and required affiliations. Outcome/reason pairs are exact:

- `ALLOW / POLICY_ALLOW`;
- `STEP_UP / HUMAN_APPROVAL_REQUIRED` with the exact required approver capability;
- `DENY` with another stable reason and no approver capability.

`DELEGATION_IDENTITIES_NOT_DISTINCT` is an issuance HTTP `400` domain error but an evaluation HTTP `200` acting-only delegated denial. Both transports are intentional and fail closed.

## 5. Issue or retain

Only a fully authority-bound `ALLOW` may receive receipt v2 inside the same Hono evaluation transaction. Every `DENY`, every `STEP_UP`, and every unbound or partially bound result is receipt-free.

Decisions and the authority artifacts actually trusted by core are retained in the in-memory log for later step-up creation and onboarding projection.

## 6. Resolve step-up

A request is created only from a retained fully bound `STEP_UP` decision. Request v2 preserves all decision bindings and expires no later than its underlying subject/delegation authority.

Resolution requires a registered active `HUMAN` approver credential matching the approver tuple. It must carry the policy-required capability, exact action `step-up:resolve`, and the original resource. Subject authority is revalidated before resolution. Only one terminal transition is accepted.

Approval creates authorization v2 bound to the request, original authority, and approver credential. Rejection creates no authorization.

## 7. Revalidate and consume

### Receipt path

The consumer supplies every expected receipt v2 binding. Verification checks exact schema, decision/reason coherence, HMAC, time, current acting credential, and—for delegated mode—the grantor credential and delegation/policy. The receipt nonce is atomically consumed once.

### Step-up path

Consumption verifies every request, authority, and approver binding; rechecks subject and approver authority; and atomically consumes the authorization once.

Revocation or expiry after decision, signing, or approval invalidates later consumption.

## 8. Present retained onboarding state

The versioned zkYA view recomputes current verification, delegated scope, action eligibility, and required approval from the retained decision ID. Receipt projection has independent axes:

- durable `consumptionStatus`: `NOT_ISSUED`, `UNCONSUMED`, or `CONSUMED`;
- `lastAttempt`: `NONE`, `ACCEPTED / RECEIPT_VALID`, or associated `REJECTED`.

Durable consumption is monotonic. Replay remains `CONSUMED` and records `REJECTED / RECEIPT_REPLAYED`; malformed or unassociated input leaves both axes unchanged. The view is local and does not execute the action.

## Execution boundary

A separate trusted adapter could use a successfully consumed authorization before downstream handoff. This repository contains no protected-action executor and cannot interrupt already-running actions.
