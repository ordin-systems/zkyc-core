import {
  DomainValidationError,
  timestampMillis,
  validateIdentifier,
  validateTimestamp,
} from "./domain.js";

export interface AtomicNonceStore {
  consume(nonce: string, expiresAt: string, at: string): Promise<boolean>;
}

export class InMemoryAtomicNonceStore implements AtomicNonceStore {
  readonly #consumed = new Map<string, number>();

  consume(nonce: string, expiresAt: string, at: string): Promise<boolean> {
    let id: string;
    let expiry: string;
    let checkedAt: string;
    try {
      id = validateIdentifier(nonce, "nonce");
      expiry = validateTimestamp(expiresAt, "nonce expiresAt");
      checkedAt = validateTimestamp(at, "nonce consumption time");
    } catch (error) {
      if (error instanceof DomainValidationError) return Promise.resolve(false);
      throw error;
    }
    const now = timestampMillis(checkedAt);
    const expires = timestampMillis(expiry);
    if (now >= expires) return Promise.resolve(false);

    for (const [storedNonce, storedExpiry] of this.#consumed) {
      if (storedExpiry <= now) this.#consumed.delete(storedNonce);
    }
    if (this.#consumed.has(id)) return Promise.resolve(false);

    // There is deliberately no await between the check and set. A JavaScript turn
    // performs this operation atomically, so Promise.all contenders have one winner.
    this.#consumed.set(id, expires);
    return Promise.resolve(true);
  }
}
