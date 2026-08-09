# Security Policy

## Scope

This repository is a reference implementation. Security reports should concern the checked-in authority model, credential lifecycle, step-up lifecycle, receipt verification, replay contract, Hono transport boundary, SDK contract, canonicalization or verification tooling.

The reference API intentionally has no authentication, tenancy, rate limiting or durable state and must not be deployed as-is. It refuses startup without a caller-supplied HMAC key of at least 32 bytes. Never report a live signing key or production endpoint in a public issue.

## Reporting

Do not include live credentials, signing keys, personal data or production endpoints in a public issue. Use ORDIN's published security contact when available; until then, open a minimal GitHub issue requesting a private reporting channel without disclosing exploit details.

## Key handling

- Never commit real signing keys.
- Tests must use deterministic non-production keys.
- Production adapters must load secrets from an approved secret manager.
- The default/reference configuration must fail closed when no signing key is supplied.

## Supported release

Security support begins only when a tagged reference release is published. The README-only landing-page state and untagged development commits are not supported releases.
