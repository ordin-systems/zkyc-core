# Receipt Key Boundary

The reference implementation accepts an HMAC key supplied by its caller and requires at least 32 bytes. Tests use fixed non-production material.

A production adapter must:

- obtain the key from an approved secret manager;
- separate test, staging and production keys;
- identify the active key version in operational metadata;
- rotate keys without silently extending receipt validity;
- avoid logging keys or complete private receipts;
- fail closed when key retrieval is unavailable or ambiguous.

This repository does not provide key storage, rotation infrastructure or a production key-management claim.
