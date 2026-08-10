import { canonicalJson, sha256Version } from "./canonical.js";
import { CredentialAuthority, type Credential } from "./credentials.js";
import { DelegationAuthority, type CapabilityDelegation } from "./delegations.js";
import {
  REASON_CODES,
  ActionSensitivity,
  createPrincipal,
  rejectUnknownKeys,
  requireRecord,
  validateAction,
  validateIdentifier,
  validateTimestamp,
  type DecisionOutcome,
  type Principal,
  type PrincipalType,
  type ReasonCode,
  type UnverifiedMetadata,
} from "./domain.js";
import { createPolicy, type Policy } from "./policy.js";

export const AUTHORITY_MODES = ["DIRECT", "DELEGATED"] as const;
export type AuthorityMode = (typeof AUTHORITY_MODES)[number];

export interface AccessDecision {
  readonly version: 2;
  readonly outcome: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly authorityMode?: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType?: PrincipalType;
  readonly actingCredentialId?: string;
  readonly effectiveScopeHash?: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  /** @deprecated Direct-mode compatibility alias. Never identifies a delegated grantor. */
  readonly credentialId?: string;
  readonly grantorId?: string;
  readonly grantorType?: PrincipalType;
  readonly grantorCredentialId?: string;
  readonly delegationId?: string;
  readonly delegationBindingHash?: string;
  readonly decidedAt: string;
  readonly requiredApproverCapability?: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

interface CommonAccessEvaluationInput {
  readonly principal: Principal;
  readonly action: string;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: Policy;
  readonly at: string;
  readonly credentialAuthority: CredentialAuthority;
}

export interface DirectAccessEvaluationInput extends CommonAccessEvaluationInput {
  readonly authorityMode: "DIRECT";
  readonly credential: Credential | null;
}

export interface DelegatedAccessEvaluationInput extends CommonAccessEvaluationInput {
  readonly authorityMode: "DELEGATED";
  readonly delegateIdentityCredential: Credential;
  readonly grantorCredential: Credential;
  readonly delegation: CapabilityDelegation;
  readonly delegationAuthority: DelegationAuthority;
}

export type AccessEvaluationInput = DirectAccessEvaluationInput | DelegatedAccessEvaluationInput;

interface ValidatedCommonInput {
  readonly authorityMode: AuthorityMode;
  readonly principal: Principal;
  readonly action: string;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policy: Policy;
  readonly at: string;
  readonly credentialAuthority: CredentialAuthority;
}

type DecisionFields = Omit<AccessDecision, "outcome" | "reasonCode">;
type DecisionBindings = Partial<
  Pick<
    AccessDecision,
    | "actingCredentialId"
    | "effectiveScopeHash"
    | "credentialId"
    | "grantorId"
    | "grantorType"
    | "grantorCredentialId"
    | "delegationId"
    | "delegationBindingHash"
  >
>;

const COMMON_INPUT_KEYS = [
  "authorityMode",
  "principal",
  "action",
  "resourceId",
  "actionContext",
  "policy",
  "at",
  "credentialAuthority",
] as const;

const DIRECT_INPUT_KEYS = [...COMMON_INPUT_KEYS, "credential"] as const;
const DELEGATED_INPUT_KEYS = [
  ...COMMON_INPUT_KEYS,
  "delegateIdentityCredential",
  "grantorCredential",
  "delegation",
  "delegationAuthority",
] as const;

function invalidDecision(at?: unknown, authorityMode?: AuthorityMode): AccessDecision {
  let decidedAt = "1970-01-01T00:00:00.000Z";
  try {
    decidedAt = validateTimestamp(at, "decision time");
  } catch {
    // The fail-closed decision intentionally uses a fixed sentinel time.
  }
  return Object.freeze({
    version: 2,
    outcome: "DENY",
    reasonCode: "INVALID_INPUT",
    ...(authorityMode === undefined ? {} : { authorityMode }),
    subjectId: "unknown",
    action: "unknown",
    actionSensitivity: ActionSensitivity.ROUTINE,
    resourceId: "unknown",
    contextHash: sha256Version({}),
    policyId: "unknown",
    policyVersion: "unknown",
    decidedAt,
  });
}

function validateExactPolicy(value: unknown): Policy {
  const record = requireRecord(value, "evaluation policy");
  rejectUnknownKeys(record, ["id", "version", "rules", "defaultEffect"], "evaluation policy");
  const policy = createPolicy({ id: record.id, rules: record.rules as never });
  if (record.version !== policy.version || record.defaultEffect !== "DENY") {
    throw new Error("evaluation policy must have its exact content-derived version");
  }
  return policy;
}

function validateCommon(
  record: Record<string, unknown>,
  authorityMode: AuthorityMode,
): ValidatedCommonInput {
  const principal = createPrincipal(record.principal);
  const action = validateAction(record.action, "action");
  const resourceId = validateIdentifier(record.resourceId, "resourceId");
  const contextHash = sha256Version(requireRecord(record.actionContext, "actionContext"));
  const policy = validateExactPolicy(record.policy);
  const at = validateTimestamp(record.at, "decision time");
  if (!(record.credentialAuthority instanceof CredentialAuthority)) {
    throw new Error("evaluation requires a credential authority");
  }
  return {
    authorityMode,
    principal,
    action,
    resourceId,
    contextHash,
    policy,
    at,
    credentialAuthority: record.credentialAuthority,
  };
}

function baseDecision(common: ValidatedCommonInput): DecisionFields {
  const rule = common.policy.rules.find((candidate) => candidate.action === common.action);
  return {
    version: 2,
    authorityMode: common.authorityMode,
    subjectId: common.principal.id,
    subjectType: common.principal.type,
    action: common.action,
    actionSensitivity: rule?.actionSensitivity ?? ActionSensitivity.ROUTINE,
    resourceId: common.resourceId,
    contextHash: common.contextHash,
    policyId: common.policy.id,
    policyVersion: common.policy.version,
    decidedAt: common.at,
  };
}

function decision(
  common: ValidatedCommonInput,
  outcome: DecisionOutcome,
  reasonCode: ReasonCode,
  bindings: DecisionBindings = {},
  metadata?: UnverifiedMetadata,
  requiredApproverCapability?: string,
): AccessDecision {
  return Object.freeze({
    outcome,
    reasonCode,
    ...baseDecision(common),
    ...bindings,
    ...(requiredApproverCapability === undefined ? {} : { requiredApproverCapability }),
    ...(metadata === undefined ? {} : { unverifiedMetadata: metadata }),
  });
}

function mappedCredentialReason(code: string): ReasonCode {
  return REASON_CODES.find((reason) => reason === code) ?? "CREDENTIAL_MALFORMED";
}

function directBindings(credential: Credential): DecisionBindings {
  return {
    actingCredentialId: credential.id,
    effectiveScopeHash: credential.scopeHash,
    credentialId: credential.id,
  };
}

function delegatedBindings(
  delegateIdentityCredential: Credential,
  delegation?: CapabilityDelegation,
): DecisionBindings {
  const acting = {
    actingCredentialId: delegateIdentityCredential.id,
    effectiveScopeHash: delegateIdentityCredential.scopeHash,
  };
  if (delegation === undefined) return acting;
  return {
    ...acting,
    effectiveScopeHash: delegation.scopeHash,
    grantorId: delegation.grantorId,
    grantorType: delegation.grantorType,
    grantorCredentialId: delegation.grantorCredentialId,
    delegationId: delegation.id,
    delegationBindingHash: delegation.delegationBindingHash,
  };
}

function exactSubjectMatch(principal: Principal, credential: Credential): boolean {
  return credential.principalId === principal.id &&
    credential.principalType === principal.type &&
    canonicalJson(credential.affiliations) === canonicalJson(principal.affiliations);
}

function evaluatePolicy(
  common: ValidatedCommonInput,
  capabilities: readonly string[],
  affiliations: Credential["affiliations"],
  bindings: DecisionBindings,
  metadata: UnverifiedMetadata | undefined,
  insufficientCapabilityReason: ReasonCode,
): AccessDecision {
  const rule = common.policy.rules.find((candidate) => candidate.action === common.action);
  if (rule === undefined) {
    return decision(common, "DENY", "ACTION_NOT_PERMITTED", bindings, metadata);
  }
  if (rule.effect === "DENY") {
    return decision(common, "DENY", "POLICY_DENY", bindings, metadata);
  }
  const granted = new Set(capabilities);
  if (!rule.requiredCapabilities.every((capability) => granted.has(capability))) {
    return decision(common, "DENY", insufficientCapabilityReason, bindings, metadata);
  }
  const affiliationKeys = new Set(
    affiliations.map((affiliation) => `${affiliation.organizationId}\u0000${affiliation.role}`),
  );
  if (
    !rule.requiredAffiliations.every((affiliation) =>
      affiliationKeys.has(`${affiliation.organizationId}\u0000${affiliation.role}`),
    )
  ) {
    return decision(common, "DENY", "AFFILIATION_REQUIRED", bindings, metadata);
  }
  if (rule.effect === "ALLOW") {
    return decision(common, "ALLOW", "POLICY_ALLOW", bindings, metadata);
  }
  return decision(
    common,
    "STEP_UP",
    "HUMAN_APPROVAL_REQUIRED",
    bindings,
    metadata,
    rule.approverCapability as string,
  );
}

function evaluateDirect(record: Record<string, unknown>, common: ValidatedCommonInput): AccessDecision {
  if (record.credential === null || record.credential === undefined) {
    return decision(common, "DENY", "CREDENTIAL_MISSING");
  }
  if (typeof record.credential !== "object" || Array.isArray(record.credential)) {
    return decision(common, "DENY", "CREDENTIAL_MALFORMED");
  }
  const credential = record.credential as Credential;
  const status = common.credentialAuthority.checkCredential(credential, common.at);
  if (!status.valid) {
    const bindings = status.code === "CREDENTIAL_MALFORMED" || status.code === "CREDENTIAL_UNKNOWN"
      ? {}
      : directBindings(credential);
    return decision(common, "DENY", mappedCredentialReason(status.code), bindings);
  }
  const bindings = directBindings(credential);
  if (!exactSubjectMatch(common.principal, credential)) {
    return decision(
      common,
      "DENY",
      "CREDENTIAL_SUBJECT_MISMATCH",
      bindings,
      credential.unverifiedMetadata,
    );
  }
  if (!credential.allowedActions.includes(common.action)) {
    return decision(
      common,
      "DENY",
      "ACTION_OUTSIDE_CREDENTIAL_SCOPE",
      bindings,
      credential.unverifiedMetadata,
    );
  }
  if (!credential.allowedResourceIds.includes(common.resourceId)) {
    return decision(
      common,
      "DENY",
      "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE",
      bindings,
      credential.unverifiedMetadata,
    );
  }
  return evaluatePolicy(
    common,
    credential.capabilities,
    credential.affiliations,
    bindings,
    credential.unverifiedMetadata,
    "INSUFFICIENT_CAPABILITY",
  );
}

function evaluateDelegated(
  record: Record<string, unknown>,
  common: ValidatedCommonInput,
): AccessDecision {
  if (!(record.delegationAuthority instanceof DelegationAuthority)) {
    return invalidDecision(common.at, "DELEGATED");
  }
  if (!record.delegationAuthority.usesCredentialAuthority(common.credentialAuthority)) {
    return decision(common, "DENY", "DELEGATION_GRANTOR_CREDENTIAL_INVALID");
  }
  if (record.delegateIdentityCredential === null || record.delegateIdentityCredential === undefined) {
    return decision(common, "DENY", "CREDENTIAL_MISSING");
  }
  if (
    typeof record.delegateIdentityCredential !== "object" ||
    Array.isArray(record.delegateIdentityCredential)
  ) {
    return decision(common, "DENY", "CREDENTIAL_MALFORMED");
  }
  const delegateIdentityCredential = record.delegateIdentityCredential as Credential;
  const delegateStatus = common.credentialAuthority.checkCredential(
    delegateIdentityCredential,
    common.at,
  );
  if (!delegateStatus.valid) {
    const bindings = delegateStatus.code === "CREDENTIAL_MALFORMED" ||
        delegateStatus.code === "CREDENTIAL_UNKNOWN"
      ? {}
      : delegatedBindings(delegateIdentityCredential);
    return decision(common, "DENY", mappedCredentialReason(delegateStatus.code), bindings);
  }
  const actingBindings = delegatedBindings(delegateIdentityCredential);
  if (!exactSubjectMatch(common.principal, delegateIdentityCredential)) {
    return decision(
      common,
      "DENY",
      "DELEGATION_DELEGATE_MISMATCH",
      actingBindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (record.delegation === null || typeof record.delegation !== "object" || Array.isArray(record.delegation)) {
    return decision(
      common,
      "DENY",
      "DELEGATION_MALFORMED",
      actingBindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  const delegation = record.delegation as CapabilityDelegation;
  const delegationStatus = record.delegationAuthority.checkDelegation(
    delegation,
    common.at,
    common.policy,
  );
  const delegationIsKnown = delegationStatus.code !== "DELEGATION_MALFORMED" &&
    delegationStatus.code !== "DELEGATION_UNKNOWN";
  const bindings = delegationIsKnown
    ? delegatedBindings(delegateIdentityCredential, delegation)
    : actingBindings;
  if (!delegationStatus.valid) {
    const mapped = REASON_CODES.find((reason) => reason === delegationStatus.code);
    return decision(
      common,
      "DENY",
      mapped ?? "DELEGATION_MALFORMED",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (
    delegation.delegateId !== common.principal.id ||
    delegation.delegateType !== common.principal.type ||
    delegation.delegateId !== delegateIdentityCredential.principalId ||
    delegation.delegateType !== delegateIdentityCredential.principalType
  ) {
    return decision(
      common,
      "DENY",
      "DELEGATION_DELEGATE_MISMATCH",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (record.grantorCredential === null || typeof record.grantorCredential !== "object" ||
      Array.isArray(record.grantorCredential)) {
    return decision(
      common,
      "DENY",
      "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  const grantorCredential = record.grantorCredential as Credential;
  const grantorStatus = common.credentialAuthority.checkCredential(grantorCredential, common.at);
  if (!grantorStatus.valid) {
    return decision(
      common,
      "DENY",
      "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (
    grantorCredential.id !== delegation.grantorCredentialId ||
    grantorCredential.principalId !== delegation.grantorId ||
    grantorCredential.principalType !== delegation.grantorType
  ) {
    return decision(
      common,
      "DENY",
      "DELEGATION_GRANTOR_MISMATCH",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (
    !grantorCredential.allowedActions.includes(common.action) ||
    !delegation.allowedActions.includes(common.action)
  ) {
    return decision(
      common,
      "DENY",
      "ACTION_OUTSIDE_DELEGATION_SCOPE",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  if (
    !grantorCredential.allowedResourceIds.includes(common.resourceId) ||
    !delegation.allowedResourceIds.includes(common.resourceId)
  ) {
    return decision(
      common,
      "DENY",
      "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
      bindings,
      delegateIdentityCredential.unverifiedMetadata,
    );
  }
  return evaluatePolicy(
    common,
    delegation.capabilities,
    delegateIdentityCredential.affiliations,
    bindings,
    delegateIdentityCredential.unverifiedMetadata,
    "INSUFFICIENT_DELEGATED_CAPABILITY",
  );
}

export function evaluateAccess(value: unknown): AccessDecision {
  let record: Record<string, unknown>;
  try {
    record = requireRecord(value, "access evaluation");
  } catch {
    return invalidDecision();
  }
  const rawMode = record.authorityMode;
  const authorityMode = rawMode === "DIRECT" || rawMode === "DELEGATED" ? rawMode : undefined;
  if (authorityMode === undefined) return invalidDecision(record.at);
  try {
    rejectUnknownKeys(
      record,
      authorityMode === "DIRECT" ? DIRECT_INPUT_KEYS : DELEGATED_INPUT_KEYS,
      "access evaluation",
    );
    const common = validateCommon(record, authorityMode);
    return authorityMode === "DIRECT"
      ? evaluateDirect(record, common)
      : evaluateDelegated(record, common);
  } catch {
    return invalidDecision(record.at, authorityMode);
  }
}
