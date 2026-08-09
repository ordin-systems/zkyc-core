export class DomainValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DomainValidationError";
  }
}

export interface Affiliation {
  readonly organizationId: string;
  readonly role: string;
}

export interface Principal {
  readonly id: string;
  readonly affiliations: readonly Affiliation[];
}

export interface UnverifiedMetadata {
  readonly zkPassProofId?: string;
  readonly contextualProofIds?: readonly string[];
}

export enum ActionSensitivity {
  ROUTINE = "ROUTINE",
  SENSITIVE = "SENSITIVE",
  CRITICAL = "CRITICAL",
}

export const DECISION_OUTCOMES = ["ALLOW", "DENY", "STEP_UP"] as const;
export type DecisionOutcome = (typeof DECISION_OUTCOMES)[number];

export const REASON_CODES = [
  "POLICY_ALLOW",
  "POLICY_DENY",
  "HUMAN_APPROVAL_REQUIRED",
  "INVALID_INPUT",
  "CREDENTIAL_MISSING",
  "CREDENTIAL_MALFORMED",
  "CREDENTIAL_UNKNOWN",
  "CREDENTIAL_NOT_YET_VALID",
  "CREDENTIAL_EXPIRED",
  "CREDENTIAL_REVOKED",
  "CREDENTIAL_SUBJECT_MISMATCH",
  "INSUFFICIENT_CAPABILITY",
  "AFFILIATION_REQUIRED",
  "ACTION_NOT_PERMITTED",
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const contextHashPattern = /^sha256:[0-9a-f]{64}$/;

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DomainValidationError(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new DomainValidationError(`${label} must be a plain object`);
  }
  return Object.fromEntries(Object.entries(value));
}

export function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(record).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) {
    throw new DomainValidationError(`${label} contains unsupported fields: ${unknown.sort().join(", ")}`);
  }
}

export function validateIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !identifierPattern.test(value)) {
    throw new DomainValidationError(`${label} must be a non-empty identifier`);
  }
  return value;
}

export function validateCapability(value: unknown, label = "capability"): string {
  return validateIdentifier(value, label);
}

export function validateAction(value: unknown, label = "action"): string {
  return validateIdentifier(value, label);
}

export function validateActionSensitivity(value: unknown, label = "actionSensitivity"): ActionSensitivity {
  if (!Object.values(ActionSensitivity).includes(value as ActionSensitivity)) {
    throw new DomainValidationError(`${label} is unsupported`);
  }
  return value as ActionSensitivity;
}

export function validateContextHash(value: unknown, label = "contextHash"): string {
  if (typeof value !== "string" || !contextHashPattern.test(value)) {
    throw new DomainValidationError(`${label} must be a canonical SHA-256 hash`);
  }
  return value;
}

export function validateTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") throw new DomainValidationError(`${label} must be an ISO timestamp`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new DomainValidationError(`${label} must be a canonical ISO timestamp`);
  }
  return value;
}

export function timestampMillis(value: string): number {
  return new Date(value).getTime();
}

function affiliationKey(affiliation: Affiliation): string {
  return `${affiliation.organizationId}\u0000${affiliation.role}`;
}

export function canonicalizeAffiliations(
  value: unknown,
  label: string,
  options: { deduplicate?: boolean } = {},
): readonly Affiliation[] {
  if (!Array.isArray(value)) throw new DomainValidationError(`${label} must be an array`);
  const affiliations = value.map((entry, index): Affiliation => {
    const affiliation = requireRecord(entry, `${label}[${index}]`);
    rejectUnknownKeys(affiliation, ["organizationId", "role"], `${label}[${index}]`);
    return Object.freeze({
      organizationId: validateIdentifier(affiliation.organizationId, `${label}[${index}].organizationId`),
      role: validateIdentifier(affiliation.role, `${label}[${index}].role`),
    });
  });
  affiliations.sort((left, right) => {
    const leftKey = affiliationKey(left);
    const rightKey = affiliationKey(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  const canonical: Affiliation[] = [];
  let previousKey: string | undefined;
  for (const affiliation of affiliations) {
    const key = affiliationKey(affiliation);
    if (key === previousKey) {
      if (options.deduplicate === true) continue;
      throw new DomainValidationError(`${label} must be unique`);
    }
    canonical.push(affiliation);
    previousKey = key;
  }
  return Object.freeze(canonical);
}

export function createPrincipal(input: unknown): Principal {
  const record = requireRecord(input, "principal");
  rejectUnknownKeys(record, ["id", "affiliations"], "principal");
  return Object.freeze({
    id: validateIdentifier(record.id, "principal.id"),
    affiliations: canonicalizeAffiliations(record.affiliations, "principal.affiliations"),
  });
}

export function validateUnverifiedMetadata(value: unknown): UnverifiedMetadata {
  const record = requireRecord(value, "unverifiedMetadata");
  rejectUnknownKeys(record, ["zkPassProofId", "contextualProofIds"], "unverifiedMetadata");
  const result: { zkPassProofId?: string; contextualProofIds?: readonly string[] } = {};
  if (record.zkPassProofId !== undefined) {
    result.zkPassProofId = validateIdentifier(record.zkPassProofId, "unverifiedMetadata.zkPassProofId");
  }
  if (record.contextualProofIds !== undefined) {
    if (!Array.isArray(record.contextualProofIds)) {
      throw new DomainValidationError("unverifiedMetadata.contextualProofIds must be an array");
    }
    const ids = record.contextualProofIds.map((id, index) =>
      validateIdentifier(id, `unverifiedMetadata.contextualProofIds[${index}]`),
    );
    if (new Set(ids).size !== ids.length) {
      throw new DomainValidationError("unverifiedMetadata.contextualProofIds must be unique");
    }
    result.contextualProofIds = Object.freeze([...ids].sort());
  }
  return Object.freeze(result);
}
