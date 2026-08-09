# Reproducibility

## Requirements

- Node.js 20.19.x or Node.js 22.12.0 or newer;
- npm with lockfile/workspace support.

## Clean verification

From a fresh copy of the exact commit:

```bash
npm ci --ignore-scripts
npm run verify
```

The one-command verification performs:

1. repository format check;
2. secret/private-path/excluded-surface security scan;
3. strict core typecheck;
4. core acceptance and regression tests;
5. strict API, SDK and UI typechecks;
6. API, SDK and React cockpit interaction tests;
7. core, API, SDK and React/Vite production builds;
8. package manifest/artifact verification plus an isolated core/API archive install and import;
9. extensionless-file publication-scanner regression;
10. dependency audit.

A passing build is not a deployment or production-readiness claim.

## Determinism

Tests use fixed identifiers, timestamps, policies and non-production keys. No network service, database, external model or live secret is required. Time-sensitive behavior uses injected clocks.

The operator UI uses wall-clock future expirations only for interactive local demonstration. Its authority scenarios mirror checked-in deterministic fixtures, while executable fixture proof runs through API and SDK tests.

## Release verification receipt

A release receipt records:

- exact Git commit and tree;
- Node, npm, OS and architecture;
- lockfile hash;
- commands and exit status;
- core/API/SDK test counts;
- UI build output;
- source archive and receipt hashes;
- public CI, tag and release URLs;
- explicit limitations.
