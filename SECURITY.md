# Security Policy

## Scope

This repository is a bounded reference implementation. Security reports should concern the checked-in authority model, credential/delegation lifecycle, step-up lifecycle, receipt verification and projection, replay contract, Hono transport boundary, SDK correlation contract, canonicalization, or verification tooling.

The reference API intentionally has no authentication, tenancy, rate limiting, or durable state and must not be deployed as-is. It refuses startup without a caller-supplied HMAC key of at least 32 bytes. Never report a live signing key or production endpoint in a public issue.

## Reporting

Do not include live credentials, signing keys, personal data, or production endpoints in a public issue. Use ORDIN's published security contact when available; until then, open a minimal GitHub issue requesting a private reporting channel without disclosing exploit details.

## Key handling

- Never commit real signing keys.
- Tests must use deterministic non-production keys.
- Production adapters must load secrets from an approved secret manager.
- The default/reference configuration must fail closed when no signing key is supplied.

## Supported release

Historical `v0.3.0` is the latest published tagged reference release. ORDIN accepts bounded security reports against that exact published source but provides no production-support or response-time guarantee.

The forward `v0.3.1` work is currently an unmerged and unpublished candidate, not a supported release. Untagged development commits and local candidate builds are never supported release artifacts. A later `v0.3.1` tag becomes a published supported reference only after its protected release and public readback gates complete.
