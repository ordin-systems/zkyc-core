import { canonicalJson, sha256Version } from "./canonical.js";
import {
  DomainValidationError,
  canonicalizeActions,
  canonicalizeAffiliations,
  canonicalizeCapabilities,
  canonicalizeResourceIds,
  createPrincipal,
  rejectUnknownKeys,
  requireRecord,
  timestampMillis,
  validateContextHash,
  validateIdentifier,
  validatePrincipalType,
  validateTimestamp,
  validateUnverifiedMetadata,
  type Affiliation,
  type Principal,
  type PrincipalType,
  type UnverifiedMetadata,
} from "./domain.js";

export interface AuthorityScope {
  readonly capabilities: readonly string[];
  readonly allowedActions: readonly string[];
  readonly allowedResourceIds: readonly string[];
}

export interface Credential extends AuthorityScope {
  readonly version: 2;
  readonly id: string;
  readonly issuerId: string;
  readonly principalId: string;
  readonly principalType: PrincipalType;
  readonly affiliations: readonly Affiliation[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly scopeHash: string;
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

export interface IssueCredentialInput extends AuthorityScope {
  readonly id: string;
  readonly principal: Principal;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

function canonicalScope(value: unknown, label: string): AuthorityScope {
  const record = requireRecord(value, label);
  rejectUnknownKeys(
    record,
    ["capabilities", "allowedActions", "allowedResourceIds"],
    label,
  );
  return Object.freeze({
    capabilities: canonicalizeCapabilities(record.capabilities, `${label}.capabilities`),
    allowedActions: canonicalizeActions(record.allowedActions, `${label}.allowedActions`),
    allowedResourceIds: canonicalizeResourceIds(
      record.allowedResourceIds,
      `${label}.allowedResourceIds`,
    ),
  });
}

export function computeScopeHash(value: unknown): string {
  const scope = canonicalScope(value, "scope");
  return sha256Version({
    domain: "zkyc-scope",
    version: 1,
    capabilities: scope.capabilities,
    allowedActions: scope.allowedActions,
    allowedResourceIds: scope.allowedResourceIds,
  });
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
      "principalType",
      "affiliations",
      "capabilities",
      "allowedActions",
      "allowedResourceIds",
      "issuedAt",
      "expiresAt",
      "scopeHash",
      "unverifiedMetadata",
    ],
    "credential",
  );
  if (record.version !== 2) throw new DomainValidationError("credential.version must be 2");
  const issuedAt = validateTimestamp(record.issuedAt, "credential.issuedAt");
  const expiresAt = validateTimestamp(record.expiresAt, "credential.expiresAt");
  if (timestampMillis(issuedAt) >= timestampMillis(expiresAt)) {
    throw new DomainValidationError("credential expiry must be after issuance");
  }
  const scope = canonicalScope(
    {
      capabilities: record.capabilities,
      allowedActions: record.allowedActions,
      allowedResourceIds: record.allowedResourceIds,
    },
    "credential scope",
  );
  const scopeHash = validateContextHash(record.scopeHash, "credential.scopeHash");
  if (scopeHash !== computeScopeHash(scope)) {
    throw new DomainValidationError("credential.scopeHash does not match credential scope");
  }
  const base = {
    version: 2 as const,
    id: validateIdentifier(record.id, "credential.id"),
    issuerId: validateIdentifier(record.issuerId, "credential.issuerId"),
    principalId: validateIdentifier(record.principalId, "credential.principalId"),
    principalType: validatePrincipalType(record.principalType, "credential.principalType"),
    affiliations: canonicalizeAffiliations(record.affiliations, "credential.affiliations"),
    ...scope,
    issuedAt,
    expiresAt,
    scopeHash,
  };
  if (record.unverifiedMetadata === undefined) return Object.freeze(base);
  return Object.freeze({ ...base, unverifiedMetadata: validateUnverifiedMetadata(record.unverifiedMetadata) });
}

export class CredentialAuthority {
  readonly issuerId: string;
  readonly #issued = new Map<string, Credential>();
  readonly #revocations = new Map<string, Revocation>();

  constructor(input: { issuerId: string }) {
    const record = requireRecord(input, "credential authority input");
    rejectUnknownKeys(record, ["issuerId"], "credential authority input");
    this.issuerId = validateIdentifier(record.issuerId, "issuerId");
  }

  issueCredential(input: IssueCredentialInput): Credential {
    const inputRecord = requireRecord(input, "credential issuance input");
    rejectUnknownKeys(
      inputRecord,
      [
        "id",
        "principal",
        "capabilities",
        "allowedActions",
        "allowedResourceIds",
        "issuedAt",
        "expiresAt",
        "unverifiedMetadata",
      ],
      "credential issuance input",
    );
    const principal = createPrincipal(inputRecord.principal);
    const scope = canonicalScope(
      {
        capabilities: inputRecord.capabilities,
        allowedActions: inputRecord.allowedActions,
        allowedResourceIds: inputRecord.allowedResourceIds,
      },
      "credential scope",
    );
    const candidate: Record<string, unknown> = {
      version: 2,
      id: inputRecord.id,
      issuerId: this.issuerId,
      principalId: principal.id,
      principalType: principal.type,
      affiliations: principal.affiliations,
      ...scope,
      issuedAt: inputRecord.issuedAt,
      expiresAt: inputRecord.expiresAt,
      scopeHash: computeScopeHash(scope),
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
    const inputRecord = requireRecord(input, "credential revocation input");
    rejectUnknownKeys(inputRecord, ["revokedAt", "reason"], "credential revocation input");
    const credential = this.#issued.get(id);
    if (credential === undefined || this.#revocations.has(id)) return false;
    const revokedAt = validateTimestamp(inputRecord.revokedAt, "revokedAt");
    if (timestampMillis(revokedAt) < timestampMillis(credential.issuedAt)) {
      throw new DomainValidationError("revocation cannot predate credential issuance");
    }
    const reason = validateIdentifier(inputRecord.reason, "revocation reason");
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
    expectedPrincipalType?: unknown,
  ): CredentialStatus {
    let id: string;
    let checkedAt: string;
    let subjectId: string | undefined;
    let subjectType: PrincipalType | undefined;
    try {
      id = validateIdentifier(credentialId, "credentialId");
      checkedAt = validateTimestamp(at, "credential check time");
      if (expectedPrincipalId !== undefined) {
        subjectId = validateIdentifier(expectedPrincipalId, "expectedPrincipalId");
      }
      if (expectedPrincipalType !== undefined) {
        subjectType = validatePrincipalType(expectedPrincipalType, "expectedPrincipalType");
      }
    } catch {
      return { valid: false, code: "CREDENTIAL_MALFORMED" };
    }
    const credential = this.#issued.get(id);
    if (
      credential === undefined ||
      (subjectId !== undefined && credential.principalId !== subjectId) ||
      (subjectType !== undefined && credential.principalType !== subjectType)
    ) {
      return { valid: false, code: "CREDENTIAL_UNKNOWN" };
    }
    return this.#statusAt(credential, checkedAt);
  }
}
