# Policy Model

## Exact policy content

A policy has a stable ID, fixed default `DENY`, and a content-derived SHA-256 version. Each action has exactly one rule. Duplicate or contradictory action rules are rejected, and evaluators recompute the version rather than trusting caller-supplied content.

A rule binds:

- exact action identifier;
- sensitivity (`ROUTINE`, `SENSITIVE`, or `CRITICAL`);
- required credential/delegation capabilities;
- required principal affiliations;
- effect (`ALLOW`, `DENY`, or `STEP_UP`);
- required approver capability for `STEP_UP` only.

Unknown actions use default `DENY`.

## Credential scope precedes policy effect

Credentials independently bind exact allowed actions and resource IDs. A policy rule cannot widen credential scope. Evaluation denies action/resource mismatch before a policy `ALLOW` can authorize it.

## Delegated policy binding

A delegation records exact policy ID and content-derived version at issuance. Delegated evaluation must present matching policy content. The effective capabilities/actions/resources are the delegation's attenuated scope, each already constrained to the grantor credential.

Required affiliations in delegated mode are checked only against the delegate identity credential. Grantor affiliations do not transfer with a delegation.

## Human step-up scope

A `STEP_UP` rule names the required approver capability. Resolution additionally requires:

- an exact `HUMAN` approver type;
- an active registered matching credential;
- action scope containing `step-up:resolve`;
- resource scope containing the original requested resource.

The step-up request/authorization retains policy ID/version and all original authority bindings. A human approval cannot change policy, action, resource, context, mode, credential, or delegation.

## Revalidation

Delegated evaluation, step-up transitions/consumption, and receipt consumption recheck the pinned policy and relevant current authority. A later policy mismatch, expiry, or revocation fails closed.

## Boundary

Policies are local in-memory reference inputs. There is no authenticated policy administration channel, tenant isolation, durable policy registry, or production policy rollout mechanism.
