# Security Policy

## Scope

This repository is a reference implementation. Security reports should concern the checked-in authority model, credential lifecycle, step-up lifecycle, receipt verification, replay contract or verification tooling.

## Reporting

Do not include live credentials, signing keys, personal data or production endpoints in a public issue. Use ORDIN's published security contact when available; until then, open a minimal GitHub issue requesting a private reporting channel without disclosing exploit details.

## Key handling

- Never commit real signing keys.
- Tests must use deterministic non-production keys.
- Production adapters must load secrets from an approved secret manager.
- The default/reference configuration must fail closed when no signing key is supplied.

## Supported release

Security support begins only when a tagged reference release is published. The README-only landing-page state and untagged development commits are not supported releases.
