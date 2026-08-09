# Decision Lifecycle

## 1. Validate

The evaluator validates the principal, credential-bound affiliations, action, resource, context, policy and evaluation time. Unsupported fields, malformed identifiers, contradictory rules and stale policy versions fail closed.

## 2. Establish credential status

The credential must be registered by the configured authority, bound to the principal, active at evaluation time and not revoked. Contextual proof identifiers do not alter credential status.

## 3. Evaluate policy

The evaluator matches the exact action rule, required affiliation constraints and required capabilities. The versioned rule returns one of:

- `ALLOW` — a trusted issuer-side adapter may construct and sign a receipt from the decision;
- `DENY` — no authorization is issued;
- `STEP_UP` — a trusted issuer-side adapter may create a bound, time-limited human-review request.

## 4. Resolve step-up

An authorized approver may approve or reject a pending request only when `requestedAt <= resolutionAt < expiresAt`. Only one terminal transition is accepted. Approval creates a one-time authorization bound to the original subject, action, sensitivity, resource, context, policy and credential.

The step-up authorization is consumed through `consumeAuthorization()`. It is not converted into a signed receipt in this reference release.

## 5. Verify and consume an ALLOW receipt

`signReceipt()` is a trusted authority primitive and does not independently prove that a plain payload came from the evaluator. The consumer-facing `verifyAndConsumeReceipt()` requires every expected binding—subject, action, sensitivity, resource, context, policy, credential, decision and reason—then checks the HMAC, time bounds and current credential status.

The receipt nonce is domain-separated through a digest and consumed through the atomic-store contract immediately before downstream handoff. Sequential or concurrent replay attempts fail. This repository does not execute the downstream action.
