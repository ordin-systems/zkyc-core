# v0.1.0-reference release notes

This is the first bounded public reference release of zKYC Core under ORDIN stewardship.

## Reviewer-verifiable capability

The release demonstrates deterministic action-authority decisions, credential expiry/revocation, human step-up handling, signed receipt verification and one-time replay consumption through an explicit atomic-store contract. Checked-in fixtures plus negative-path and concurrency tests run without a network, database, external model or secret.

## Important limitations

- Reference implementation only; not a production deployment.
- The included nonce store is in-memory; production adapters must implement durable atomic compare-and-set semantics.
- No network authentication, tenancy, webhooks, payments or external-model authority are included.
- Contextual `zkPassProofId` values are metadata only. The release does not verify zero-knowledge proofs.
- Public source availability does not grant reuse rights unless ORDIN adds an explicit license.

## Verification

Run the exact clean verification bundle documented in `REPRODUCIBILITY.md`. Release-specific commit, archive and lockfile hashes are recorded in the published verification receipt.
