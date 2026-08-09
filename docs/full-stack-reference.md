# v0.2 Full-Stack Reference

## Purpose

The full-stack reference makes the authority lifecycle inspectable without changing the deterministic core's authority hierarchy.

```text
React/Vite reviewer cockpit
            ↓ typed calls
TypeScript SDK
            ↓ JSON transport
Hono trusted authority adapter
            ↓ validated core inputs
Deterministic zKYC evaluator
            ↓
ALLOW | DENY | STEP_UP + reason
```

## Workspaces

### Hono API — `apps/core-api`

The adapter owns a `CredentialAuthority`, `HumanStepUpService`, atomic nonce store and in-memory decision log. It injects clock, identifiers and HMAC key, making tests deterministic.

It strengthens trusted-adapter provenance:

- there is no generic receipt-signing endpoint;
- a receipt is constructed only from the `ALLOW` produced by the current evaluation request;
- evaluator results are retained by generated log ID;
- step-up creation accepts only a retained log ID and expiry;
- arbitrary decision objects and unknown fields fail closed.

### SDK — `packages/sdk`

The SDK exposes typed methods for every public route and accepts injected `fetch` for browser, test and alternate-runtime use. Successful and error responses are runtime-validated against exact route schemas before typed values are returned. Reason-coded authority outcomes remain normal response values. HTTP API failures and network/invalid-response failures use distinct error classes.

### Operator cockpit — `apps/operator-ui`

The cockpit demonstrates three bounded scenarios:

- routine read → `ALLOW` + signed receipt;
- critical delete → `DENY` without receipt;
- sensitive export → `STEP_UP` + approval/rejection.

It can verify and consume a receipt or approved step-up authorization once and display defensive-copy reason-coded decision/receipt log entries. Receipt history exposes the signed payload, algorithm and a hash of the signature—not the reusable signature itself. The cockpit has no control for executing the requested action.

## State boundary

Credentials, revocations, retained decisions, step-up requests, logs and nonces are in-memory reference state. Restarting the API clears them. Production adapters require authenticated administration and transactional durable stores.

## Authentication boundary

The API deliberately contains no authentication, tenancy or authorization for administrative routes. It is executable evidence and must not be deployed as-is.

## Receipt-key boundary

The server refuses to start unless `ZKYC_RECEIPT_HMAC_KEY` contains at least 32 bytes. No default key is checked in. Keys are never returned or logged.

## UI boundary

The UI is a reviewer interface, not an identity-verification product, production dashboard or protected-action executor. It does not expose raw signing controls, arbitrary policy editors or signing-key input.
