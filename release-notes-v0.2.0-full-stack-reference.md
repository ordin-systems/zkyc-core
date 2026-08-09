# v0.2.0 Full-Stack Reference Release Notes

This successor release adds reviewer-verifiable full-stack adapters around the deterministic zKYC authority core.

## Included

- Hono reference API;
- TypeScript SDK;
- React/Vite operator cockpit;
- reason-coded in-memory decision/receipt history;
- deterministic full-stack fixtures;
- core, API, SDK and UI automated tests;
- CI-backed core/API/SDK/UI typechecks and builds;
- canonicalization correction for own `__proto__` keys with regressions.

## Trust boundaries

- receipts are issued only from same-request `ALLOW` evaluator output;
- step-up requests are created only from retained evaluator decisions;
- receipt consumers provide every fixed semantic expected binding;
- all state remains in-memory and reference-only;
- the API has no authentication and must not be deployed as-is;
- the UI never executes protected actions;
- no KYC/AML, ZK verification, external-model authority, webhooks, payments or real-funds execution.

## Lineage

`v0.1.0-reference` remains immutable. This release is a successor and does not alter the earlier source archive, tag, verification receipt or release record.

## License

`UNLICENSED` / all rights reserved. No reuse license is granted.
