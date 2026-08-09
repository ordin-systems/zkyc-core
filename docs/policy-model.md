# Policy Model

A policy is identified by a stable ID and a content-derived version. Each action has exactly one rule.

A rule binds:

- exact action identifier;
- action sensitivity (`ROUTINE`, `SENSITIVE` or `CRITICAL`);
- zero or more required principal affiliations;
- zero or more required credential capabilities;
- effect (`ALLOW`, `DENY` or `STEP_UP`);
- required approver capability for `STEP_UP` only.

Duplicate or contradictory action rules are rejected. Unknown actions use the policy's fixed default effect, `DENY`.

Policy versions are generated from canonical policy content. Evaluators recompute the version and reject caller-supplied policy objects whose content does not match the version.
