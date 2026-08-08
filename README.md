# zKYC Core

**Agent Identity and Action-Authority Decision Infrastructure**

> **Publication status:** Evidence landing page. The canonical public reference source, automated verification, public CI, provenance documentation, and release artifacts are being prepared. This repository does not yet contain the public reference source.

zKYC Core is an agent identity and action-authority decision reference implementation originated and architected by [Mike “Mizzy” Barrera](https://github.com/mizzysworld) during his tenure as Chief Agentic Officer at zKYC. Stewardship and canonical maintenance of the technology transferred to [ORDIN](https://github.com/ordin-systems) in 2026.

## Current audited implementation boundary

The current private publication candidate includes:

- Hono API
- React/Vite operator interface
- TypeScript SDK source
- Configurable action tiers
- Deterministic `ALLOW`, `DENY`, and `STEP_UP` outcomes
- Reason-coded decision logs
- Human resolution for escalated cases
- HMAC-signed decision receipts
- Replay-tracking metadata
- `zkPassProofId` as contextual integration input

The audited implementation accepts `zkPassProofId` as context; it does **not** verify a zero-knowledge proof.

## Hardening required before a public reference release

- Enforced credential expiry and revocation semantics
- Receipt verification
- Atomic replay protection
- Deterministic fixtures and automated API/SDK tests
- Clean locked installation and coherent workspace commands
- SDK build repair
- Dependency-security remediation
- Public CI-backed UI, API, and SDK builds
- Authentication and per-user authorization appropriate to the reference scope
- Architecture, threat model, decision-lifecycle, provenance, authorship, limitations, and verification documentation

Until those gates pass, this landing page should not be interpreted as evidence that the target hardened release already exists.

## Ownership and provenance

ORDIN is the canonical owner and maintainer. The public release will include `PROVENANCE.md` and `AUTHORS.md` documenting original context, architecture, stewardship transfer, current maintenance responsibility, publication rights, and verified contribution boundaries.
