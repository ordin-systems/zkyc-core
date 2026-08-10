# Principal and Delegation Model

## Typed principals

Every validated principal has an identifier, an exact type, and zero or more affiliations:

- `HUMAN` — required for step-up approvers;
- `ORGANIZATION` — may act directly or be a delegation grantor;
- `AGENT` — may act directly or as a delegation delegate.

A credential v2 binds `principalId`, `principalType`, credential-bound affiliations, capabilities, exact allowed actions, exact allowed resource IDs, issuer, issuance/expiry, and a canonical scope hash. Caller-presented principal fields must match the registered credential tuple. Principal type is an executable binding, not descriptive metadata.

## Direct authority

`DIRECT` evaluation uses one acting credential for the subject. The evaluator checks:

1. exact registered credential content and active validity;
2. subject ID, subject type, and affiliation equality;
3. exact credential action and resource scope;
4. required policy capabilities and affiliations;
5. exact content-derived policy version.

The decision binds `authorityMode`, typed subject, `actingCredentialId`, `effectiveScopeHash`, action, sensitivity, resource, context hash, policy, outcome/reason, and time.

## Delegated authority

`DELEGATED` evaluation requires three separate registered artifacts:

1. the delegate's identity credential, which establishes the acting subject's ID, type, and affiliations;
2. the grantor's root credential, which establishes the grantor's available capability/action/resource scope;
3. a registered one-hop delegation issued by the same configured authority.

The delegation binds its issuer, grantor ID/type/credential, delegate ID/type, policy ID/version, validity interval, exact capabilities/actions/resources, scope hash, and a domain-separated delegation binding hash.

The acting credential and grantor credential are not interchangeable. A delegated decision binds both identity lanes and the delegation ID/hash.

## Attenuation and no affiliation transfer

Delegated capabilities, actions, and resources must each be subsets of the grantor credential's corresponding scope. A delegation cannot include `delegation:issue`, so delegated authority cannot be used to redelegate. The model is one hop; it does not accept a delegation chain.

Grantor affiliations are never copied to the delegate. Policy affiliation checks in delegated mode use only affiliations established by the delegate's own identity credential. A grant can confer bounded capability/action/resource authority, not organizational membership.

## Policy, time, and revocation

Delegation issuance pins exact policy ID and content-derived version. Evaluation fails closed if the presented policy differs. A delegation cannot outlive its grantor credential.

The relevant authority is revalidated after issuance:

- delegated evaluation checks the delegate identity credential, grantor credential, delegation registration, policy, expiry, and revocation;
- step-up request creation, resolution, and consumption recheck subject authority;
- receipt consumption rechecks acting authority and, for delegated mode, grantor/delegation authority;
- retained onboarding views recompute current credential/delegation status.

Revocation or expiry therefore invalidates later use even when an earlier decision, approval, or receipt was valid.

## Human step-up boundary

Only a `HUMAN` principal may resolve a step-up request. The registered approver credential must:

- match the human principal ID/type and affiliations;
- remain active;
- contain the policy-required approver capability;
- allow exact action `step-up:resolve`;
- allow the original requested resource.

Step-up request and authorization v2 preserve the original direct/delegated bindings. Approval does not widen scope or turn a delegated path into a direct path. Consumption verifies the complete expected binding and consumes its nonce once.

## Receipt v2

An `ALLOW / POLICY_ALLOW` may produce an HMAC-SHA256 receipt v2 only through the trusted adapter's evaluation transaction. Receipt v2 binds:

- direct/delegated mode;
- subject ID/type, acting credential, and effective scope hash;
- action, sensitivity, resource, context, policy ID/version, outcome, and reason;
- direct credential ID, or delegated grantor ID/type/credential plus delegation ID/binding hash;
- nonce and decision/issuance/expiry times.

The consumer supplies the complete expected authority binding. Verification checks structure, HMAC, coherence, time, current authority, and atomic nonce consumption. HMAC is a shared-secret reference trust domain, not an asymmetric public attestation.

## Maturity boundary

This is a local deterministic authority model. It is not identity proofing, KYC/AML, ZK verification, network authentication, durable delegation infrastructure, protected-action execution, or production security.
