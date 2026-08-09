# Claims and Limitations

## Supported claims

The verified reference implementation supports the following bounded claims:

- deterministic evaluation of principal, credential, capability, permission and action-policy inputs;
- reason-coded `ALLOW`, `DENY` and `STEP_UP` outcomes;
- credential expiry and revocation checks;
- human step-up approval, rejection and expiry;
- HMAC-signed, time-bounded decision receipts;
- timing-safe signature verification;
- one-time replay consumption through an explicit atomic store contract;
- deterministic fixtures and automated tests.

## Non-claims

This repository does not establish:

- zero-knowledge-proof verification;
- production deployment or production security;
- external adoption, validation or independent replication;
- durable distributed replay protection from the in-memory adapter alone;
- network authentication, tenancy or rate limiting;
- payment execution, x402 behavior or custody of funds;
- safety of arbitrary external integrations;
- automatic proof that a structurally valid plain receipt/request object originated from `evaluateAccess()`—issuer-side callers of `signReceipt()` and `createRequest()` are trusted authority adapters.

`zkPassProofId` and similar identifiers are contextual metadata only. They are not accepted as proof of cryptographic verification.
