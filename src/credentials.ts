import { canonicalJson } from "./canonical.js";
import {
  DomainValidationError,
  canonicalizeAffiliations,
  createPrincipal,
  rejectUnknownKeys,
  requireRecord,
  timestampMillis,
  validateCapability,
  validateIdentifier,
  validateTimestamp,
  validateUnverifiedMetadata,
  type Affiliation,
  type Principal,
  type UnverifiedMetadata,
} from "./domain.js";

export interface Credential {
  readonly version: 1;
  readonly id: string;
  readonly issuerId: string;
  readonly principalId: string;
  readonly affiliations: readonly Affiliation[];
  readonly capabilities: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export type CredentialStatusCode =
  | "ACTIVE"
  | "CREDENTIAL_MALFORMED"
  | "CREDENTIAL_UNKNOWN"
  | "CREDENTIAL_NOT_YET_VALID"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_REVOKED";

export interface CredentialStatus {
  readonly valid: boolean;
  readonly code: CredentialStatusCode;
}

interface Revocation {
  readonly revokedAt: string;
  readonly reason: string;
}

export interface IssueCredentialInput {
  readonly id: string;
  readonly principal: Principal;
  readonly capabilities: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

function validateCredential(value: unknown): Credential {
  const record = requireRecord(value, "credential");
  rejectUnknownKeys(
    record,
    [
      "version",
      "id",
      "issuerId",
      "principalId",
      "affiliations",
      "capabilities",
      "issuedAt",
      "expiresAt",
      "unverifiedMetadata",
    ],
    "credential",
  );
  if (record.version !== 1) throw new DomainValidationError("credential.version must be 1");
  if (!Array.isArray(record.capabilities)) {
    throw new DomainValidationError("credential.capabilities must be an array");
  }
  const capabilities = record.capabilities.map((capability, index) =>
    validateCapability(capability, `credential.capabilities[${index}]`),
  );
  if (new Set(capabilities).size !== capabilities.length) {
    throw new DomainValidationError("credential capabilities must be unique");
  }
  capabilities.sort();
  const issuedAt = validateTimestamp(record.issuedAt, "credential.issuedAt");
  const expiresAt = validateTimestamp(record.expiresAt, "credential.expiresAt");
  if (timestampMillis(issuedAt) >= timestampMillis(expiresAt)) {
    throw new DomainValidationError("credential expiry must be after issuance");
  }
  const base = {
    version: 1 as const,
    id: validateIdentifier(record.id, "credential.id"),
    issuerId: validateIdentifier(record.issuerId, "credential.issuerId"),
    principalId: validateIdentifier(record.principalId, "credential.principalId"),
    affiliations: canonicalizeAffiliations(record.affiliations, "credential.affiliations"),
    capabilities: Object.freeze(capabilities),
    issuedAt,
    expiresAt,
  };
  if (record.unverifiedMetadata === undefined) return Object.freeze(base);
  return Object.freeze({ ...base, unverifiedMetadata: validateUnverifiedMetadata(record.unverifiedMetadata) });
}

export class CredentialAuthority {
  readonly issuerId: string;
  readonly #issued = new Map<string, Credential>();
  readonly #revocations = new Map<string, Revocation>();

  constructor(input: { issuerId: string }) {
    this.issuerId = validateIdentifier(input.issuerId, "issuerId");
  }

  issueCredential(input: IssueCredentialInput): Credential {
    const inputRecord = requireRecord(input, "credential issuance input");
    rejectUnknownKeys(
      inputRecord,
      ["id", "principal", "capabilities", "issuedAt", "expiresAt", "unverifiedMetadata"],
      "credential issuance input",
    );
    const principal = createPrincipal(inputRecord.principal);
    const candidate: Record<string, unknown> = {
      version: 1,
      id: inputRecord.id,
      issuerId: this.issuerId,
      principalId: principal.id,
      affiliations: principal.affiliations,
      capabilities: inputRecord.capabilities,
      issuedAt: inputRecord.issuedAt,
      expiresAt: inputRecord.expiresAt,
    };
    if (inputRecord.unverifiedMetadata !== undefined) {
      candidate.unverifiedMetadata = inputRecord.unverifiedMetadata;
    }
    const credential = validateCredential(candidate);
    if (this.#issued.has(credential.id)) {
      throw new DomainValidationError(`credential already exists: ${credential.id}`);
    }
    this.#issued.set(credential.id, credential);
    return credential;
  }

  revokeCredential(
    credentialId: string,
    input: { revokedAt: string; reason: string },
  ): boolean {
    const id = validateIdentifier(credentialId, "credentialId");
    const credential = this.#issued.get(id);
    if (credential === undefined || this.#revocations.has(id)) return false;
    const revokedAt = validateTimestamp(input.revokedAt, "revokedAt");
    if (timestampMillis(revokedAt) < timestampMillis(credential.issuedAt)) {
      throw new DomainValidationError("revocation cannot predate credential issuance");
    }
    const reason = validateIdentifier(input.reason, "revocation reason");
    this.#revocations.set(id, Object.freeze({ revokedAt, reason }));
    return true;
  }

  #statusAt(credential: Credential, checkedAt: string): CredentialStatus {
    const now = timestampMillis(checkedAt);
    if (now < timestampMillis(credential.issuedAt)) {
      return { valid: false, code: "CREDENTIAL_NOT_YET_VALID" };
    }
    if (now >= timestampMillis(credential.expiresAt)) {
      return { valid: false, code: "CREDENTIAL_EXPIRED" };
    }
    const revocation = this.#revocations.get(credential.id);
    if (revocation !== undefined && now >= timestampMillis(revocation.revokedAt)) {
      return { valid: false, code: "CREDENTIAL_REVOKED" };
    }
    return { valid: true, code: "ACTIVE" };
  }

  checkCredential(value: unknown, at: string): CredentialStatus {
    let credential: Credential;
    let checkedAt: string;
    try {
      credential = validateCredential(value);
      checkedAt = validateTimestamp(at, "credential check time");
    } catch {
      return { valid: false, code: "CREDENTIAL_MALFORMED" };
    }
    if (credential.issuerId !== this.issuerId) return { valid: false, code: "CREDENTIAL_UNKNOWN" };
    const registered = this.#issued.get(credential.id);
    if (registered === undefined || canonicalJson(registered) !== canonicalJson(credential)) {
      return { valid: false, code: "CREDENTIAL_UNKNOWN" };
    }
    return this.#statusAt(registered, checkedAt);
  }

  checkCredentialById(
    credentialId: unknown,
    at: unknown,
    expectedPrincipalId?: unknown,
  ): CredentialStatus {
    let id: string;
    let checkedAt: string;
    let subjectId: string | undefined;
    try {
      id = validateIdentifier(credentialId, "credentialId");
      checkedAt = validateTimestamp(at, "credential check time");
      if (expectedPrincipalId !== undefined) {
        subjectId = validateIdentifier(expectedPrincipalId, "expectedPrincipalId");
      }
    } catch {
      return { valid: false, code: "CREDENTIAL_MALFORMED" };
    }
    const credential = this.#issued.get(id);
    if (credential === undefined || (subjectId !== undefined && credential.principalId !== subjectId)) {
      return { valid: false, code: "CREDENTIAL_UNKNOWN" };
    }
    return this.#statusAt(credential, checkedAt);
  }
}
