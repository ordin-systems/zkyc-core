# Reproducibility

## Requirements

- Node.js 20 or newer
- npm with lockfile support

## Clean verification

From a fresh copy of the exact commit:

```bash
npm ci
npm run format:check
npm run security:check
npm run typecheck
npm test
npm run build
npm run verify
npm audit --audit-level=high
```

The verification command must execute checked-in fixtures through the same public API used by automated tests. A passing build is not a claim of deployment or production readiness.

## Determinism

Tests use fixed identifiers, timestamps, policies and keys. No network, database, external model or secret is required. Time-sensitive behavior is exercised through an injected clock rather than wall-clock waiting.

## Receipt verification

A release verification receipt should record:

- exact Git commit;
- Node and npm versions;
- lockfile hash;
- commands and exit status;
- test inventory and pass count;
- build artifact hash;
- explicit limitations.
