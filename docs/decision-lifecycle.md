# Decision Lifecycle

## 1. Validate typed input

The evaluator validates exact principal type/identity/affiliations, authority mode, credentials, delegation when present, action, resource, canonical context, content-versioned policy, and evaluation time. Unknown fields, mixed direct/delegated fields, malformed identifiers, contradictory rules, and stale policy content fail closed.

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

## 3. Evaluate exact policy

The content-derived policy version is recomputed. The exact action rule checks sensitivity, required capabilities, and required affiliations. The evaluator returns:

- `ALLOW / POLICY_ALLOW`;
- `DENY` with a stable reason code;
- `STEP_UP / HUMAN_APPROVAL_REQUIRED` with the required approver capability.

Decision v2 binds authority mode, typed subject, acting credential, effective scope, action/resource/context, policy, time, and direct or delegated authority fields.

## 4. Issue or retain

For `ALLOW`, the Hono adapter may issue receipt v2 inside the same evaluation transaction. `DENY` and `STEP_UP` never receive receipts. Every decision and its authority artifacts are retained in the in-memory log for later step-up creation and onboarding projection.

## 5. Resolve step-up

A request is created only from a retained `STEP_UP` decision. Request v2 preserves all decision bindings and expires no later than its underlying subject/delegation authority.

Resolution requires a registered active `HUMAN` approver credential matching the approver tuple. It must carry the policy-required capability, exact action `step-up:resolve`, and the original resource. Subject authority is revalidated before resolution. Only one terminal transition is accepted.

Approval creates authorization v2 bound to the request, original authority, and approver credential. Rejection creates no authorization.

## 6. Revalidate and consume

### Receipt path

The consumer supplies every expected receipt v2 binding. Verification checks exact schema, decision/reason coherence, HMAC, time, current acting credential, and—for delegated mode—the grantor credential and delegation/policy. The receipt nonce is atomically consumed once.

### Step-up path

Consumption verifies every request, authority, and approver binding; rechecks subject and approver authority; and atomically consumes the authorization once.

Revocation or expiry after decision/signing/approval invalidates later consumption.

## 7. Present retained onboarding state

The versioned zkYA view recomputes current verification, delegated-scope, action eligibility, required approval, and receipt state from the retained decision ID. It is a local view and does not execute the action.

## Execution boundary

A separate trusted adapter could use a successfully consumed authorization before downstream handoff. This repository contains no protected-action executor and cannot interrupt already-running actions.
