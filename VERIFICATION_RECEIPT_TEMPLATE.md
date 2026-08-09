# Verification Receipt Template

- **Repository:** `https://github.com/ordin-systems/zkyc-core`
- **Commit:** `<exact SHA>`
- **Tag:** `<tag or untagged>`
- **Verified at:** `<UTC timestamp>`
- **Node:** `<version>`
- **npm:** `<version>`
- **Lockfile SHA-256:** `<hash>`
- **Build artifact SHA-256:** `<hash>`

## Commands

| Command | Exit | Result |
|---|---:|---|
| `npm ci` |  |  |
| `npm run format:check` |  |  |
| `npm run security:check` |  |  |
| `npm run typecheck` |  |  |
| `npm test` |  |  |
| `npm run build` |  |  |
| `npm run verify` |  |  |
| `npm audit --audit-level=high` |  |  |

## Test inventory

`<exact test count and named behavioral lanes>`

## Limitations

Reference implementation only. No production deployment, external validation, ZK-proof verification, network authentication, durable distributed store, webhook or payment execution is implied.
