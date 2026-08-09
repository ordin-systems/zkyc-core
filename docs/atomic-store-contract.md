# Atomic Store Contract

`AtomicNonceStore.consume(nonce, expiresAt, at)` is the execution-boundary replay primitive.

A conforming adapter must:

1. validate the nonce and time inputs;
2. reject consumption at or after expiry;
3. perform the unused-check and used-state transition as one indivisible operation;
4. return `true` to exactly one contender;
5. return `false` to every later or concurrent contender;
6. preserve the used state durably until expiry;
7. fail closed when the backing store is unavailable or ambiguous.

The included in-memory adapter demonstrates the contract inside one JavaScript process. It is not evidence of distributed durability. A database adapter should use a unique nonce key and a single conditional insert/update transaction; an external cache adapter should use an atomic set-if-absent operation with an expiry.

Downstream action adapters must call the high-level verify-and-consume operation immediately before handoff. Cryptographic inspection without successful atomic consumption is not authorization to execute.
