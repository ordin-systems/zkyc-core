# Extraction Rationale

The historical isolated demo was not used as the public source tree because it combined several unrelated and unsafe-for-reference surfaces:

- fixed demo-user middleware rather than real authorization;
- an external LLM response treated as the action classification authority;
- direct webhook delivery;
- x402 payment execution;
- non-atomic receipt use tracking;
- dependency and SDK-build failures;
- no test or CI proof chain.

The public reference is therefore a fresh, narrow extraction of the authority model. It uses deterministic policy as the sole authority, has no runtime network dependency and excludes action execution. This improves reviewer verifiability while preventing the release from implying production safety or deployment maturity.
