import { canonicalJson, sha256Version } from "./canonical.js";
import {
  CredentialAuthority,
  computeScopeHash,
  type AuthorityScope,
  type Credential,
} from "./credentials.js";
import {
  DomainValidationError,
  canonicalizeActions,
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
  type Principal,
  type PrincipalType,
} from "./domain.js";
import { createPolicy, type Policy } from "./policy.js";

export interface CapabilityDelegation extends AuthorityScope {
  readonly version: 1;
  readonly id: string;
  readonly issuerId: string;
  readonly grantorCredentialId: string;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly delegateId: string;
  readonly delegateType: PrincipalType;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly scopeHash: string;
  readonly delegationBindingHash: string;
}

export interface IssueDelegationInput extends AuthorityScope {
  readonly id: string;
  readonly grantor: Principal;
  readonly grantorCredential: Credential;
  readonly delegate: Principal;
  readonly policy: Policy;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export type DelegationValidationCode =
  | "DELEGATION_MALFORMED"
  | "DELEGATION_ALREADY_EXISTS"
  | "DELEGATION_GRANTOR_CREDENTIAL_INVALID"
  | "DELEGATION_GRANTOR_MISMATCH"
  | "DELEGATION_SCOPE_ESCALATION"
  | "DELEGATION_POLICY_INVALID"
  | "DELEGATION_TIME_INVALID"
  | "DELEGATION_REDELEGATION_NOT_ALLOWED";

export class DelegationValidationError extends DomainValidationError {
  readonly code: DelegationValidationCode;

  constructor(code: DelegationValidationCode, message: string) {
    super(message);
    this.name = "DelegationValidationError";
    this.code = code;
  }
}

export type DelegationStatusCode =
  | "ACTIVE"
  | "DELEGATION_MALFORMED"
  | "DELEGATION_UNKNOWN"
  | "DELEGATION_NOT_YET_VALID"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_REVOKED"
  | "DELEGATION_GRANTOR_CREDENTIAL_INVALID"
  | "DELEGATION_POLICY_MISMATCH";

export interface DelegationStatus {
  readonly valid: boolean;
  readonly code: DelegationStatusCode;
}

interface Revocation {
  readonly revokedAt: string;
  readonly reason: string;
}

interface DelegationBindingFields extends AuthorityScope {
  readonly version: 1;
  readonly id: string;
  readonly issuerId: string;
  readonly grantorCredentialId: string;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly delegateId: string;
  readonly delegateType: PrincipalType;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly scopeHash: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "delegation validation failed";
}

function validateRegisteredPolicy(value: unknown): Policy {
  const record = requireRecord(value, "delegation policy");
  rejectUnknownKeys(record, ["id", "version", "defaultEffect", "rules"], "delegation policy");
  const policy = createPolicy({ id: record.id, rules: record.rules as never });
  if (record.version !== policy.version || record.defaultEffect !== policy.defaultEffect) {
    throw new DelegationValidationError(
      "DELEGATION_POLICY_INVALID",
      "delegation policy must have its content-derived version and default effect",
    );
  }
  return policy;
}

function canonicalDelegationScope(
  value: { capabilities: unknown; allowedActions: unknown; allowedResourceIds: unknown },
): AuthorityScope {
  return Object.freeze({
    capabilities: canonicalizeCapabilities(value.capabilities, "delegation.capabilities", {
      requireNonEmpty: true,
    }),
    allowedActions: canonicalizeActions(value.allowedActions, "delegation.allowedActions", {
      requireNonEmpty: true,
    }),
    allowedResourceIds: canonicalizeResourceIds(
      value.allowedResourceIds,
      "delegation.allowedResourceIds",
      { requireNonEmpty: true },
    ),
  });
}

function delegationBindingFields(value: CapabilityDelegation): DelegationBindingFields {
  return {
    version: value.version,
    id: value.id,
    issuerId: value.issuerId,
    grantorCredentialId: value.grantorCredentialId,
    grantorId: value.grantorId,
    grantorType: value.grantorType,
    delegateId: value.delegateId,
    delegateType: value.delegateType,
    policyId: value.policyId,
    policyVersion: value.policyVersion,
    capabilities: value.capabilities,
    allowedActions: value.allowedActions,
    allowedResourceIds: value.allowedResourceIds,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    scopeHash: value.scopeHash,
  };
}

export function computeDelegationBindingHash(value: CapabilityDelegation): string {
  return sha256Version({
    domain: "zkyc-delegation-binding",
    version: 1,
    delegation: delegationBindingFields(value),
  });
}

function validateDelegation(value: unknown): CapabilityDelegation {
  const record = requireRecord(value, "delegation");
  rejectUnknownKeys(
    record,
    [
      "version",
      "id",
      "issuerId",
      "grantorCredentialId",
      "grantorId",
      "grantorType",
      "delegateId",
      "delegateType",
      "policyId",
      "policyVersion",
      "capabilities",
      "allowedActions",
      "allowedResourceIds",
      "issuedAt",
      "expiresAt",
      "scopeHash",
      "delegationBindingHash",
    ],
    "delegation",
  );
  if (record.version !== 1) {
    throw new DomainValidationError("delegation.version must be 1");
  }
  const issuedAt = validateTimestamp(record.issuedAt, "delegation.issuedAt");
  const expiresAt = validateTimestamp(record.expiresAt, "delegation.expiresAt");
  if (timestampMillis(issuedAt) >= timestampMillis(expiresAt)) {
    throw new DomainValidationError("delegation expiry must be after issuance");
  }
  const scope = canonicalDelegationScope({
    capabilities: record.capabilities,
    allowedActions: record.allowedActions,
    allowedResourceIds: record.allowedResourceIds,
  });
  const scopeHash = validateContextHash(record.scopeHash, "delegation.scopeHash");
  if (scopeHash !== computeScopeHash(scope)) {
    throw new DomainValidationError("delegation.scopeHash does not match delegation scope");
  }
  const candidate: CapabilityDelegation = Object.freeze({
    version: 1,
    id: validateIdentifier(record.id, "delegation.id"),
    issuerId: validateIdentifier(record.issuerId, "delegation.issuerId"),
    grantorCredentialId: validateIdentifier(
      record.grantorCredentialId,
      "delegation.grantorCredentialId",
    ),
    grantorId: validateIdentifier(record.grantorId, "delegation.grantorId"),
    grantorType: validatePrincipalType(record.grantorType, "delegation.grantorType"),
    delegateId: validateIdentifier(record.delegateId, "delegation.delegateId"),
    delegateType: validatePrincipalType(record.delegateType, "delegation.delegateType"),
    policyId: validateIdentifier(record.policyId, "delegation.policyId"),
    policyVersion: validateContextHash(record.policyVersion, "delegation.policyVersion"),
    ...scope,
    issuedAt,
    expiresAt,
    scopeHash,
    delegationBindingHash: validateContextHash(
      record.delegationBindingHash,
      "delegation.delegationBindingHash",
    ),
  });
  if (candidate.delegationBindingHash !== computeDelegationBindingHash(candidate)) {
    throw new DomainValidationError(
      "delegation.delegationBindingHash does not match immutable delegation fields",
    );
  }
  return candidate;
}

function isSubset(subset: readonly string[], superset: readonly string[]): boolean {
  const allowed = new Set(superset);
  return subset.every((entry) => allowed.has(entry));
}

export class DelegationAuthority {
  readonly issuerId: string;
  readonly #credentialAuthority: CredentialAuthority;
  readonly #issued = new Map<string, CapabilityDelegation>();
  readonly #revocations = new Map<string, Revocation>();

  constructor(input: { issuerId: string; credentialAuthority: CredentialAuthority }) {
    const record = requireRecord(input, "delegation authority input");
    rejectUnknownKeys(
      record,
      ["issuerId", "credentialAuthority"],
      "delegation authority input",
    );
    this.issuerId = validateIdentifier(record.issuerId, "delegation authority issuerId");
    if (!(record.credentialAuthority instanceof CredentialAuthority)) {
      throw new DelegationValidationError(
        "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
        "delegation authority requires a credential authority",
      );
    }
    this.#credentialAuthority = record.credentialAuthority;
  }

  usesCredentialAuthority(value: unknown): boolean {
    return value === this.#credentialAuthority;
  }

  issueDelegation(input: IssueDelegationInput): CapabilityDelegation {
    try {
      const record = requireRecord(input, "delegation issuance input");
      rejectUnknownKeys(
        record,
        [
          "id",
          "grantor",
          "grantorCredential",
          "delegate",
          "policy",
          "capabilities",
          "allowedActions",
          "allowedResourceIds",
          "issuedAt",
          "expiresAt",
        ],
        "delegation issuance input",
      );
      const id = validateIdentifier(record.id, "delegation.id");
      if (this.#issued.has(id)) {
        throw new DelegationValidationError(
          "DELEGATION_ALREADY_EXISTS",
          `delegation already exists: ${id}`,
        );
      }
      const grantor = createPrincipal(record.grantor);
      const delegate = createPrincipal(record.delegate);
      const policy = validateRegisteredPolicy(record.policy);
      const issuedAt = validateTimestamp(record.issuedAt, "delegation.issuedAt");
      const expiresAt = validateTimestamp(record.expiresAt, "delegation.expiresAt");
      if (timestampMillis(issuedAt) >= timestampMillis(expiresAt)) {
        throw new DelegationValidationError(
          "DELEGATION_TIME_INVALID",
          "delegation expiry must be after issuance",
        );
      }
      const grantorCredential = record.grantorCredential as Credential;
      const grantorStatus = this.#credentialAuthority.checkCredential(grantorCredential, issuedAt);
      if (!grantorStatus.valid) {
        throw new DelegationValidationError(
          "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
          `grantor credential is not an exact active registered root credential: ${grantorStatus.code}`,
        );
      }
      if (
        grantorCredential.principalId !== grantor.id ||
        grantorCredential.principalType !== grantor.type
      ) {
        throw new DelegationValidationError(
          "DELEGATION_GRANTOR_MISMATCH",
          "grantor identity tuple does not match grantor credential",
        );
      }
      if (timestampMillis(expiresAt) > timestampMillis(grantorCredential.expiresAt)) {
        throw new DelegationValidationError(
          "DELEGATION_TIME_INVALID",
          "delegation expiry cannot exceed grantor credential expiry",
        );
      }
      const scope = canonicalDelegationScope({
        capabilities: record.capabilities,
        allowedActions: record.allowedActions,
        allowedResourceIds: record.allowedResourceIds,
      });
      if (scope.capabilities.some((capability) => capability === "delegation:issue")) {
        throw new DelegationValidationError(
          "DELEGATION_REDELEGATION_NOT_ALLOWED",
          "delegation authority cannot itself be delegated",
        );
      }
      if (
        !isSubset(scope.capabilities, grantorCredential.capabilities) ||
        !isSubset(scope.allowedActions, grantorCredential.allowedActions) ||
        !isSubset(scope.allowedResourceIds, grantorCredential.allowedResourceIds)
      ) {
        throw new DelegationValidationError(
          "DELEGATION_SCOPE_ESCALATION",
          "delegated capabilities, actions and resources must each attenuate grantor scope",
        );
      }
      const scopeHash = computeScopeHash(scope);
      const unsigned: CapabilityDelegation = {
        version: 1,
        id,
        issuerId: this.issuerId,
        grantorCredentialId: grantorCredential.id,
        grantorId: grantor.id,
        grantorType: grantor.type,
        delegateId: delegate.id,
        delegateType: delegate.type,
        policyId: policy.id,
        policyVersion: policy.version,
        ...scope,
        issuedAt,
        expiresAt,
        scopeHash,
        delegationBindingHash: `sha256:${"0".repeat(64)}`,
      };
      const delegation = validateDelegation({
        ...unsigned,
        delegationBindingHash: computeDelegationBindingHash(unsigned),
      });
      this.#issued.set(delegation.id, delegation);
      return delegation;
    } catch (error) {
      if (error instanceof DelegationValidationError) throw error;
      throw new DelegationValidationError("DELEGATION_MALFORMED", errorMessage(error));
    }
  }

  revokeDelegation(
    delegationId: unknown,
    input: { revokedAt: string; reason: string },
  ): boolean {
    try {
      const id = validateIdentifier(delegationId, "delegationId");
      const record = requireRecord(input, "delegation revocation input");
      rejectUnknownKeys(record, ["revokedAt", "reason"], "delegation revocation input");
      const delegation = this.#issued.get(id);
      if (delegation === undefined || this.#revocations.has(id)) return false;
      const revokedAt = validateTimestamp(record.revokedAt, "delegation revokedAt");
      if (timestampMillis(revokedAt) < timestampMillis(delegation.issuedAt)) {
        throw new DelegationValidationError(
          "DELEGATION_TIME_INVALID",
          "revocation cannot predate delegation issuance",
        );
      }
      const reason = validateIdentifier(record.reason, "delegation revocation reason");
      this.#revocations.set(id, Object.freeze({ revokedAt, reason }));
      return true;
    } catch (error) {
      if (error instanceof DelegationValidationError) throw error;
      throw new DelegationValidationError("DELEGATION_MALFORMED", errorMessage(error));
    }
  }

  checkDelegation(value: unknown, at: unknown, expectedPolicy?: unknown): DelegationStatus {
    let delegation: CapabilityDelegation;
    let checkedAt: string;
    try {
      delegation = validateDelegation(value);
      checkedAt = validateTimestamp(at, "delegation check time");
    } catch {
      return Object.freeze({ valid: false, code: "DELEGATION_MALFORMED" });
    }
    if (delegation.issuerId !== this.issuerId) {
      return Object.freeze({ valid: false, code: "DELEGATION_UNKNOWN" });
    }
    const registered = this.#issued.get(delegation.id);
    if (registered === undefined || canonicalJson(registered) !== canonicalJson(delegation)) {
      return Object.freeze({ valid: false, code: "DELEGATION_UNKNOWN" });
    }
    if (expectedPolicy !== undefined) {
      let policy: Policy;
      try {
        policy = validateRegisteredPolicy(expectedPolicy);
      } catch {
        return Object.freeze({ valid: false, code: "DELEGATION_POLICY_MISMATCH" });
      }
      if (registered.policyId !== policy.id || registered.policyVersion !== policy.version) {
        return Object.freeze({ valid: false, code: "DELEGATION_POLICY_MISMATCH" });
      }
    }
    const now = timestampMillis(checkedAt);
    if (now < timestampMillis(registered.issuedAt)) {
      return Object.freeze({ valid: false, code: "DELEGATION_NOT_YET_VALID" });
    }
    if (now >= timestampMillis(registered.expiresAt)) {
      return Object.freeze({ valid: false, code: "DELEGATION_EXPIRED" });
    }
    const revocation = this.#revocations.get(registered.id);
    if (revocation !== undefined && now >= timestampMillis(revocation.revokedAt)) {
      return Object.freeze({ valid: false, code: "DELEGATION_REVOKED" });
    }
    const credentialStatus = this.#credentialAuthority.checkCredentialById(
      registered.grantorCredentialId,
      checkedAt,
      registered.grantorId,
      registered.grantorType,
    );
    if (!credentialStatus.valid) {
      return Object.freeze({
        valid: false,
        code: "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      });
    }
    return Object.freeze({ valid: true, code: "ACTIVE" });
  }

  checkDelegationById(
    delegationId: unknown,
    at: unknown,
    expectedPolicy?: unknown,
  ): DelegationStatus {
    let id: string;
    try {
      id = validateIdentifier(delegationId, "delegationId");
    } catch {
      return Object.freeze({ valid: false, code: "DELEGATION_MALFORMED" });
    }
    const delegation = this.#issued.get(id);
    if (delegation === undefined) {
      return Object.freeze({ valid: false, code: "DELEGATION_UNKNOWN" });
    }
    return this.checkDelegation(delegation, at, expectedPolicy);
  }
}
