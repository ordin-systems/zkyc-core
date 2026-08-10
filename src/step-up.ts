import { canonicalJson, sha256Version } from "./canonical.js";
import { CredentialAuthority, type Credential } from "./credentials.js";
import { DelegationAuthority, type CapabilityDelegation } from "./delegations.js";
import {
  DomainValidationError,
  PrincipalType,
  createPrincipal,
  rejectUnknownKeys,
  requireRecord,
  timestampMillis,
  validateAction,
  validateActionSensitivity,
  validateCapability,
  validateContextHash,
  validateIdentifier,
  validatePrincipalType,
  validateTimestamp,
  validateUnverifiedMetadata,
  type ActionSensitivity,
  type Principal,
  type PrincipalType as PrincipalTypeValue,
} from "./domain.js";
import {
  revalidateLiveDecisionAuthority,
  type AccessDecision,
  type AuthorityMode,
  type LiveDecisionAuthorityBinding,
} from "./evaluation.js";
import type { AtomicNonceStore } from "./nonce.js";
import type { Policy } from "./policy.js";

export type StepUpStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

interface CommonStepUpRequest {
  readonly version: 2;
  readonly id: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalTypeValue;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly requestedAt: string;
  readonly expiresAt: string;
  readonly status: StepUpStatus;
}

export interface DirectStepUpRequest extends CommonStepUpRequest {
  readonly authorityMode: "DIRECT";
  /** @deprecated Direct-mode compatibility alias. Never identifies a delegated grantor. */
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpRequest extends CommonStepUpRequest {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalTypeValue;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type StepUpRequest = DirectStepUpRequest | DelegatedStepUpRequest;

interface CommonStepUpAuthorization {
  readonly version: 2;
  readonly id: string;
  readonly requestId: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalTypeValue;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly approvedBy: string;
  readonly approvedByType: PrincipalTypeValue;
  readonly approverCredentialId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface DirectStepUpAuthorization extends CommonStepUpAuthorization {
  readonly authorityMode: "DIRECT";
  /** @deprecated Direct-mode compatibility alias. Never identifies a delegated grantor. */
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpAuthorization extends CommonStepUpAuthorization {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalTypeValue;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type StepUpAuthorization = DirectStepUpAuthorization | DelegatedStepUpAuthorization;

interface CommonStepUpAuthorizationBinding {
  readonly requestId: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalTypeValue;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly approvedBy: string;
  readonly approvedByType: PrincipalTypeValue;
  readonly approverCredentialId: string;
}

export interface DirectStepUpAuthorizationBinding extends CommonStepUpAuthorizationBinding {
  readonly authorityMode: "DIRECT";
  /** @deprecated Optional direct-mode compatibility assertion. */
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpAuthorizationBinding extends CommonStepUpAuthorizationBinding {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalTypeValue;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type StepUpAuthorizationBinding =
  | DirectStepUpAuthorizationBinding
  | DelegatedStepUpAuthorizationBinding;

export type StepUpFailureCode =
  | "STEP_UP_NOT_FOUND"
  | "STEP_UP_EXPIRED"
  | "STEP_UP_ALREADY_RESOLVED"
  | "STEP_UP_REJECTED"
  | "SUBJECT_AUTHORITY_INVALID"
  | "APPROVER_CREDENTIAL_INVALID"
  | "APPROVER_CAPABILITY_MISSING"
  | "APPROVER_SCOPE_MISSING"
  | "INVALID_INPUT";

export type StepUpResolutionResult =
  | { readonly ok: true; readonly authorization: StepUpAuthorization }
  | { readonly ok: false; readonly reasonCode: StepUpFailureCode };

export type StepUpAuthorizationUsabilityCode =
  | "STEP_UP_AUTHORIZATION_USABLE"
  | "STEP_UP_AUTHORIZATION_CONSUMED"
  | "STEP_UP_NOT_FOUND"
  | "STEP_UP_NOT_YET_VALID"
  | "STEP_UP_EXPIRED"
  | "SUBJECT_AUTHORITY_INVALID"
  | "APPROVER_CREDENTIAL_INVALID"
  | "APPROVER_CREDENTIAL_REVOKED"
  | "APPROVER_CREDENTIAL_EXPIRED"
  | "APPROVER_CAPABILITY_MISSING"
  | "APPROVER_SCOPE_MISSING"
  | "INVALID_INPUT";

export type StepUpAuthorizationUsability =
  | { readonly usable: true; readonly reasonCode: "STEP_UP_AUTHORIZATION_USABLE" }
  | { readonly usable: false; readonly reasonCode: Exclude<
    StepUpAuthorizationUsabilityCode,
    "STEP_UP_AUTHORIZATION_USABLE"
  > };

interface RequestRecord {
  request: StepUpRequest;
  readonly policy: Policy;
  authorization?: StepUpAuthorization;
}

interface ActiveRequestArtifacts {
  readonly actingCredential: Credential;
  readonly grantorCredential?: Credential;
  readonly delegation?: CapabilityDelegation;
}

type ValidatedDirectStepUpDecision = AccessDecision & {
  readonly authorityMode: "DIRECT";
  readonly subjectType: PrincipalTypeValue;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly requiredApproverCapability: string;
};

type ValidatedDelegatedStepUpDecision = AccessDecision & {
  readonly authorityMode: "DELEGATED";
  readonly subjectType: PrincipalTypeValue;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly requiredApproverCapability: string;
  readonly grantorId: string;
  readonly grantorType: PrincipalTypeValue;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
};

type ValidatedStepUpDecision =
  | ValidatedDirectStepUpDecision
  | ValidatedDelegatedStepUpDecision;

const ACCESS_DECISION_KEYS = [
  "version",
  "outcome",
  "reasonCode",
  "authorityMode",
  "subjectId",
  "subjectType",
  "actingCredentialId",
  "effectiveScopeHash",
  "action",
  "actionSensitivity",
  "resourceId",
  "contextHash",
  "policyId",
  "policyVersion",
  "credentialId",
  "grantorId",
  "grantorType",
  "grantorCredentialId",
  "delegationId",
  "delegationBindingHash",
  "decidedAt",
  "requiredApproverCapability",
  "unverifiedMetadata",
] as const;

const COMMON_AUTHORIZATION_KEYS = [
  "version",
  "id",
  "requestId",
  "authorityMode",
  "subjectId",
  "subjectType",
  "actingCredentialId",
  "effectiveScopeHash",
  "action",
  "actionSensitivity",
  "resourceId",
  "contextHash",
  "policyId",
  "policyVersion",
  "requiredApproverCapability",
  "approvedBy",
  "approvedByType",
  "approverCredentialId",
  "issuedAt",
  "expiresAt",
] as const;

const DELEGATED_BINDING_KEYS = [
  "grantorId",
  "grantorType",
  "grantorCredentialId",
  "delegationId",
  "delegationBindingHash",
] as const;

function minimumExpiry(...values: readonly string[]): string {
  return values.reduce((minimum, candidate) =>
    timestampMillis(candidate) < timestampMillis(minimum) ? candidate : minimum
  );
}

function validateDecision(value: unknown): ValidatedStepUpDecision {
  const record = requireRecord(value, "step-up decision");
  rejectUnknownKeys(record, ACCESS_DECISION_KEYS, "step-up decision");
  if (
    record.version !== 2 ||
    record.outcome !== "STEP_UP" ||
    record.reasonCode !== "HUMAN_APPROVAL_REQUIRED"
  ) {
    throw new DomainValidationError(
      "step-up requests require a v2 STEP_UP/HUMAN_APPROVAL_REQUIRED decision",
    );
  }
  const authorityMode = record.authorityMode;
  if (authorityMode !== "DIRECT" && authorityMode !== "DELEGATED") {
    throw new DomainValidationError("step-up decision authorityMode is required");
  }
  const common = {
    version: 2 as const,
    outcome: "STEP_UP" as const,
    reasonCode: "HUMAN_APPROVAL_REQUIRED" as const,
    authorityMode,
    subjectId: validateIdentifier(record.subjectId, "step-up decision.subjectId"),
    subjectType: validatePrincipalType(record.subjectType, "step-up decision.subjectType"),
    actingCredentialId: validateIdentifier(
      record.actingCredentialId,
      "step-up decision.actingCredentialId",
    ),
    effectiveScopeHash: validateContextHash(
      record.effectiveScopeHash,
      "step-up decision.effectiveScopeHash",
    ),
    action: validateAction(record.action, "step-up decision.action"),
    actionSensitivity: validateActionSensitivity(
      record.actionSensitivity,
      "step-up decision.actionSensitivity",
    ),
    resourceId: validateIdentifier(record.resourceId, "step-up decision.resourceId"),
    contextHash: validateContextHash(record.contextHash, "step-up decision.contextHash"),
    policyId: validateIdentifier(record.policyId, "step-up decision.policyId"),
    policyVersion: validateContextHash(
      record.policyVersion,
      "step-up decision.policyVersion",
    ),
    decidedAt: validateTimestamp(record.decidedAt, "step-up decision.decidedAt"),
    requiredApproverCapability: validateCapability(
      record.requiredApproverCapability,
      "step-up decision.requiredApproverCapability",
    ),
    ...(record.unverifiedMetadata === undefined
      ? {}
      : { unverifiedMetadata: validateUnverifiedMetadata(record.unverifiedMetadata) }),
  };
  if (authorityMode === "DIRECT") {
    for (const key of DELEGATED_BINDING_KEYS) {
      if (record[key] !== undefined) {
        throw new DomainValidationError(`direct step-up decision cannot contain ${key}`);
      }
    }
    if (record.credentialId === undefined) {
      return Object.freeze({ ...common, authorityMode: "DIRECT" as const });
    }
    const credentialId = validateIdentifier(record.credentialId, "step-up decision.credentialId");
    if (credentialId !== common.actingCredentialId) {
      throw new DomainValidationError("direct credential alias must equal actingCredentialId");
    }
    return Object.freeze({
      ...common,
      authorityMode: "DIRECT" as const,
      credentialId,
    });
  }
  if (record.credentialId !== undefined) {
    throw new DomainValidationError("delegated step-up decision cannot use credentialId as grantor");
  }
  return Object.freeze({
    ...common,
    authorityMode: "DELEGATED" as const,
    grantorId: validateIdentifier(record.grantorId, "step-up decision.grantorId"),
    grantorType: validatePrincipalType(record.grantorType, "step-up decision.grantorType"),
    grantorCredentialId: validateIdentifier(
      record.grantorCredentialId,
      "step-up decision.grantorCredentialId",
    ),
    delegationId: validateIdentifier(record.delegationId, "step-up decision.delegationId"),
    delegationBindingHash: validateContextHash(
      record.delegationBindingHash,
      "step-up decision.delegationBindingHash",
    ),
  });
}

function validateAuthorization(value: unknown): StepUpAuthorization {
  const record = requireRecord(value, "step-up authorization");
  const authorityMode = record.authorityMode;
  if (authorityMode !== "DIRECT" && authorityMode !== "DELEGATED") {
    throw new DomainValidationError("step-up authorization authorityMode is required");
  }
  rejectUnknownKeys(
    record,
    authorityMode === "DIRECT"
      ? [...COMMON_AUTHORIZATION_KEYS, "credentialId"]
      : [...COMMON_AUTHORIZATION_KEYS, ...DELEGATED_BINDING_KEYS],
    "step-up authorization",
  );
  if (record.version !== 2) {
    throw new DomainValidationError("step-up authorization.version must be 2");
  }
  const issuedAt = validateTimestamp(record.issuedAt, "step-up authorization.issuedAt");
  const expiresAt = validateTimestamp(record.expiresAt, "step-up authorization.expiresAt");
  if (timestampMillis(issuedAt) >= timestampMillis(expiresAt)) {
    throw new DomainValidationError("step-up authorization expiry must be after issuance");
  }
  const common = {
    version: 2 as const,
    id: validateIdentifier(record.id, "step-up authorization.id"),
    requestId: validateIdentifier(record.requestId, "step-up authorization.requestId"),
    authorityMode,
    subjectId: validateIdentifier(record.subjectId, "step-up authorization.subjectId"),
    subjectType: validatePrincipalType(
      record.subjectType,
      "step-up authorization.subjectType",
    ),
    actingCredentialId: validateIdentifier(
      record.actingCredentialId,
      "step-up authorization.actingCredentialId",
    ),
    effectiveScopeHash: validateContextHash(
      record.effectiveScopeHash,
      "step-up authorization.effectiveScopeHash",
    ),
    action: validateAction(record.action, "step-up authorization.action"),
    actionSensitivity: validateActionSensitivity(
      record.actionSensitivity,
      "step-up authorization.actionSensitivity",
    ),
    resourceId: validateIdentifier(record.resourceId, "step-up authorization.resourceId"),
    contextHash: validateContextHash(
      record.contextHash,
      "step-up authorization.contextHash",
    ),
    policyId: validateIdentifier(record.policyId, "step-up authorization.policyId"),
    policyVersion: validateContextHash(
      record.policyVersion,
      "step-up authorization.policyVersion",
    ),
    requiredApproverCapability: validateCapability(
      record.requiredApproverCapability,
      "step-up authorization.requiredApproverCapability",
    ),
    approvedBy: validateIdentifier(record.approvedBy, "step-up authorization.approvedBy"),
    approvedByType: validatePrincipalType(
      record.approvedByType,
      "step-up authorization.approvedByType",
    ),
    approverCredentialId: validateIdentifier(
      record.approverCredentialId,
      "step-up authorization.approverCredentialId",
    ),
    issuedAt,
    expiresAt,
  };
  if (authorityMode === "DIRECT") {
    if (record.credentialId === undefined) {
      return Object.freeze({ ...common, authorityMode: "DIRECT" as const });
    }
    const credentialId = validateIdentifier(
      record.credentialId,
      "step-up authorization.credentialId",
    );
    if (credentialId !== common.actingCredentialId) {
      throw new DomainValidationError("direct credential alias must equal actingCredentialId");
    }
    return Object.freeze({
      ...common,
      authorityMode: "DIRECT" as const,
      credentialId,
    });
  }
  return Object.freeze({
    ...common,
    authorityMode: "DELEGATED" as const,
    grantorId: validateIdentifier(record.grantorId, "step-up authorization.grantorId"),
    grantorType: validatePrincipalType(
      record.grantorType,
      "step-up authorization.grantorType",
    ),
    grantorCredentialId: validateIdentifier(
      record.grantorCredentialId,
      "step-up authorization.grantorCredentialId",
    ),
    delegationId: validateIdentifier(
      record.delegationId,
      "step-up authorization.delegationId",
    ),
    delegationBindingHash: validateContextHash(
      record.delegationBindingHash,
      "step-up authorization.delegationBindingHash",
    ),
  });
}

export class HumanStepUpService {
  readonly #credentialAuthority: CredentialAuthority;
  readonly #delegationAuthority: DelegationAuthority | undefined;
  readonly #nonceStore: AtomicNonceStore;
  readonly #requests = new Map<string, RequestRecord>();
  readonly #authorizations = new Map<string, StepUpAuthorization>();
  readonly #consumedAuthorizationIds = new Set<string>();

  constructor(input: {
    credentialAuthority: CredentialAuthority;
    delegationAuthority?: DelegationAuthority;
    nonceStore: AtomicNonceStore;
  }) {
    const record = requireRecord(input, "step-up service input");
    rejectUnknownKeys(
      record,
      ["credentialAuthority", "delegationAuthority", "nonceStore"],
      "step-up service input",
    );
    if (!(record.credentialAuthority instanceof CredentialAuthority)) {
      throw new DomainValidationError("credentialAuthority is required");
    }
    if (
      record.delegationAuthority !== undefined &&
      !(record.delegationAuthority instanceof DelegationAuthority)
    ) {
      throw new DomainValidationError("delegationAuthority must be a DelegationAuthority");
    }
    if (
      record.delegationAuthority instanceof DelegationAuthority &&
      !record.delegationAuthority.usesCredentialAuthority(record.credentialAuthority)
    ) {
      throw new DomainValidationError(
        "delegationAuthority must use the step-up service credentialAuthority",
      );
    }
    if (
      typeof record.nonceStore !== "object" ||
      record.nonceStore === null ||
      typeof (record.nonceStore as AtomicNonceStore).consume !== "function"
    ) {
      throw new DomainValidationError("an AtomicNonceStore is required");
    }
    this.#credentialAuthority = record.credentialAuthority;
    this.#delegationAuthority = record.delegationAuthority as DelegationAuthority | undefined;
    this.#nonceStore = record.nonceStore as AtomicNonceStore;
  }

  createRequest(input: {
    id: string;
    decision: AccessDecision;
    expiresAt: string;
  }): StepUpRequest {
    const inputRecord = requireRecord(input, "step-up request creation input");
    rejectUnknownKeys(
      inputRecord,
      ["id", "decision", "expiresAt"],
      "step-up request creation input",
    );
    const id = validateIdentifier(inputRecord.id, "step-up request id");
    if (this.#requests.has(id)) {
      throw new DomainValidationError(`step-up request already exists: ${id}`);
    }
    const decision = validateDecision(inputRecord.decision);
    const policy = this.#credentialAuthority.resolvePolicy(decision.policyId, decision.policyVersion);
    if (policy === undefined) {
      throw new DomainValidationError("step-up decision policy is not trusted");
    }
    const requestedAt = decision.decidedAt;
    const expiresAt = validateTimestamp(inputRecord.expiresAt, "step-up expiresAt");
    if (timestampMillis(expiresAt) <= timestampMillis(requestedAt)) {
      throw new DomainValidationError("step-up expiry must be after request time");
    }
    const artifacts = this.#activeDecisionArtifacts(decision, policy, requestedAt);
    if (artifacts === undefined) {
      throw new DomainValidationError("step-up decision authority is not currently valid");
    }
    const authorityExpiry = minimumExpiry(
      artifacts.actingCredential.expiresAt,
      ...(artifacts.grantorCredential === undefined
        ? []
        : [artifacts.grantorCredential.expiresAt]),
      ...(artifacts.delegation === undefined ? [] : [artifacts.delegation.expiresAt]),
    );
    if (timestampMillis(expiresAt) > timestampMillis(authorityExpiry)) {
      throw new DomainValidationError("step-up expiry exceeds an authority artifact expiry");
    }
    const common = {
      version: 2 as const,
      id,
      authorityMode: decision.authorityMode,
      subjectId: decision.subjectId,
      subjectType: decision.subjectType,
      actingCredentialId: decision.actingCredentialId,
      effectiveScopeHash: decision.effectiveScopeHash,
      action: decision.action,
      actionSensitivity: decision.actionSensitivity,
      resourceId: decision.resourceId,
      contextHash: decision.contextHash,
      policyId: decision.policyId,
      policyVersion: decision.policyVersion,
      requiredApproverCapability: decision.requiredApproverCapability,
      requestedAt,
      expiresAt,
      status: "PENDING" as const,
    };
    const request: StepUpRequest = decision.authorityMode === "DIRECT"
      ? Object.freeze({
        ...common,
        authorityMode: "DIRECT" as const,
        ...(decision.credentialId === undefined
          ? {}
          : { credentialId: decision.credentialId }),
      })
      : Object.freeze({
        ...common,
        authorityMode: "DELEGATED" as const,
        grantorId: decision.grantorId,
        grantorType: decision.grantorType,
        grantorCredentialId: decision.grantorCredentialId,
        delegationId: decision.delegationId,
        delegationBindingHash: decision.delegationBindingHash,
      });
    this.#requests.set(id, { request, policy });
    return request;
  }

  getRequest(id: string): StepUpRequest | undefined {
    const record = this.#requests.get(id);
    return record?.request;
  }

  async resolveRequest(input: {
    requestId: string;
    resolution: "APPROVE" | "REJECT";
    approver: Principal;
    approverCredential: Credential;
    at: string;
  }): Promise<StepUpResolutionResult> {
    let requestId: string;
    let resolution: "APPROVE" | "REJECT";
    let at: string;
    let approver: Principal;
    let approverCredential: Credential;
    try {
      const record = requireRecord(input, "step-up resolution input");
      rejectUnknownKeys(
        record,
        ["requestId", "resolution", "approver", "approverCredential", "at"],
        "step-up resolution input",
      );
      requestId = validateIdentifier(record.requestId, "requestId");
      if (record.resolution !== "APPROVE" && record.resolution !== "REJECT") {
        return { ok: false, reasonCode: "INVALID_INPUT" };
      }
      resolution = record.resolution;
      at = validateTimestamp(record.at, "resolution time");
      approver = createPrincipal(record.approver);
      approverCredential = record.approverCredential as Credential;
    } catch {
      return { ok: false, reasonCode: "INVALID_INPUT" };
    }
    const record = this.#requests.get(requestId);
    if (record === undefined) return { ok: false, reasonCode: "STEP_UP_NOT_FOUND" };
    const request = record.request;
    const policy = this.#credentialAuthority.resolvePolicy(request.policyId, request.policyVersion);
    if (policy === undefined || canonicalJson(policy) !== canonicalJson(record.policy)) {
      return { ok: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" };
    }
    if (request.status !== "PENDING") {
      return { ok: false, reasonCode: "STEP_UP_ALREADY_RESOLVED" };
    }
    if (timestampMillis(at) < timestampMillis(request.requestedAt)) {
      return { ok: false, reasonCode: "INVALID_INPUT" };
    }
    if (timestampMillis(at) >= timestampMillis(request.expiresAt)) {
      record.request = Object.freeze({ ...request, status: "EXPIRED" });
      return { ok: false, reasonCode: "STEP_UP_EXPIRED" };
    }
    const artifacts = this.#activeRequestArtifacts(request, policy, at);
    if (artifacts === undefined) {
      return { ok: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" };
    }
    if (approver.type !== PrincipalType.HUMAN) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    if (typeof approverCredential !== "object" || approverCredential === null) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    if (
      approverCredential.principalId !== approver.id ||
      approverCredential.principalType !== approver.type ||
      canonicalJson(approverCredential.affiliations) !== canonicalJson(approver.affiliations)
    ) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    const approverStatus = this.#credentialAuthority.checkCredential(approverCredential, at);
    if (!approverStatus.valid) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    if (!approverCredential.capabilities.includes(request.requiredApproverCapability)) {
      return { ok: false, reasonCode: "APPROVER_CAPABILITY_MISSING" };
    }
    if (
      !approverCredential.allowedActions.includes("step-up:resolve") ||
      !approverCredential.allowedResourceIds.includes(request.resourceId)
    ) {
      return { ok: false, reasonCode: "APPROVER_SCOPE_MISSING" };
    }
    if (resolution === "REJECT") {
      record.request = Object.freeze({ ...request, status: "REJECTED" });
      return { ok: false, reasonCode: "STEP_UP_REJECTED" };
    }

    const authorizationExpiresAt = minimumExpiry(
      request.expiresAt,
      approverCredential.expiresAt,
      artifacts.actingCredential.expiresAt,
      ...(artifacts.grantorCredential === undefined
        ? []
        : [artifacts.grantorCredential.expiresAt]),
      ...(artifacts.delegation === undefined ? [] : [artifacts.delegation.expiresAt]),
    );
    if (timestampMillis(authorizationExpiresAt) <= timestampMillis(at)) {
      return { ok: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" };
    }
    const commonBody = {
      requestId: request.id,
      authorityMode: request.authorityMode,
      subjectId: request.subjectId,
      subjectType: request.subjectType,
      actingCredentialId: request.actingCredentialId,
      effectiveScopeHash: request.effectiveScopeHash,
      action: request.action,
      actionSensitivity: request.actionSensitivity,
      resourceId: request.resourceId,
      contextHash: request.contextHash,
      policyId: request.policyId,
      policyVersion: request.policyVersion,
      requiredApproverCapability: request.requiredApproverCapability,
      approvedBy: approver.id,
      approvedByType: approver.type,
      approverCredentialId: approverCredential.id,
      issuedAt: at,
      expiresAt: authorizationExpiresAt,
    };
    const authorizationBody = request.authorityMode === "DIRECT"
      ? {
        ...commonBody,
        authorityMode: "DIRECT" as const,
        ...(request.credentialId === undefined ? {} : { credentialId: request.credentialId }),
      }
      : {
        ...commonBody,
        authorityMode: "DELEGATED" as const,
        grantorId: request.grantorId,
        grantorType: request.grantorType,
        grantorCredentialId: request.grantorCredentialId,
        delegationId: request.delegationId,
        delegationBindingHash: request.delegationBindingHash,
      };
    const authorization = Object.freeze({
      version: 2 as const,
      id: `authorization:${sha256Version(authorizationBody).slice("sha256:".length)}`,
      ...authorizationBody,
    }) as StepUpAuthorization;
    record.request = Object.freeze({ ...request, status: "APPROVED" });
    record.authorization = authorization;
    this.#authorizations.set(authorization.id, authorization);
    return { ok: true, authorization };
  }

  async consumeAuthorization(
    input: StepUpAuthorizationBinding & {
      readonly authorization: StepUpAuthorization;
      readonly at: string;
    },
  ): Promise<boolean> {
    try {
      const inputRecord = requireRecord(input, "step-up authorization consumption input");
      const authorization = validateAuthorization(inputRecord.authorization);
      const registered = this.#authorizations.get(authorization.id);
      if (
        registered === undefined ||
        canonicalJson(registered) !== canonicalJson(authorization)
      ) {
        return false;
      }
      const allowedKeys = registered.authorityMode === "DIRECT"
        ? [
          "authorization",
          "at",
          ...COMMON_AUTHORIZATION_KEYS.filter((key) =>
            key !== "version" && key !== "id" && key !== "issuedAt" && key !== "expiresAt"
          ),
          "credentialId",
        ]
        : [
          "authorization",
          "at",
          ...COMMON_AUTHORIZATION_KEYS.filter((key) =>
            key !== "version" && key !== "id" && key !== "issuedAt" && key !== "expiresAt"
          ),
          ...DELEGATED_BINDING_KEYS,
        ];
      rejectUnknownKeys(
        inputRecord,
        allowedKeys,
        "step-up authorization consumption input",
      );
      const at = validateTimestamp(inputRecord.at, "authorization consumption time");
      const requestRecord = this.#requests.get(registered.requestId);
      const policy = this.#credentialAuthority.resolvePolicy(registered.policyId, registered.policyVersion);
      if (requestRecord === undefined || policy === undefined ||
        canonicalJson(policy) !== canonicalJson(requestRecord.policy)
      ) {
        return false;
      }
      const expected = this.#validateExpectedBinding(inputRecord, registered.authorityMode);
      if (!this.#matchesExpectedBinding(registered, expected)) return false;
      if (!this.#inspectRegisteredAuthorization(registered, policy, at).usable) return false;
      const consumed = await this.#nonceStore.consume(
        `step-up-authorization:${registered.id}`,
        registered.expiresAt,
        at,
      );
      if (consumed) this.#consumedAuthorizationIds.add(registered.id);
      return consumed;
    } catch {
      return false;
    }
  }

  inspectAuthorization(input: {
    readonly authorization: StepUpAuthorization;
    readonly at: string;
  }): StepUpAuthorizationUsability {
    try {
      const inputRecord = requireRecord(input, "step-up authorization inspection input");
      rejectUnknownKeys(
        inputRecord,
        ["authorization", "at"],
        "step-up authorization inspection input",
      );
      const authorization = validateAuthorization(inputRecord.authorization);
      const registered = this.#authorizations.get(authorization.id);
      if (
        registered === undefined ||
        canonicalJson(registered) !== canonicalJson(authorization)
      ) {
        return { usable: false, reasonCode: "STEP_UP_NOT_FOUND" };
      }
      const at = validateTimestamp(inputRecord.at, "authorization inspection time");
      const requestRecord = this.#requests.get(registered.requestId);
      const policy = this.#credentialAuthority.resolvePolicy(registered.policyId, registered.policyVersion);
      if (requestRecord === undefined || policy === undefined ||
        canonicalJson(policy) !== canonicalJson(requestRecord.policy)
      ) {
        return { usable: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" };
      }
      return this.#inspectRegisteredAuthorization(registered, policy, at);
    } catch {
      return { usable: false, reasonCode: "INVALID_INPUT" };
    }
  }

  #inspectRegisteredAuthorization(
    authorization: StepUpAuthorization,
    policy: Policy,
    at: string,
  ): StepUpAuthorizationUsability {
    const requestRecord = this.#requests.get(authorization.requestId);
    if (
      requestRecord?.authorization === undefined ||
      requestRecord.request.status !== "APPROVED" ||
      canonicalJson(requestRecord.authorization) !== canonicalJson(authorization)
    ) {
      return { usable: false, reasonCode: "STEP_UP_NOT_FOUND" };
    }
    if (timestampMillis(at) < timestampMillis(authorization.issuedAt)) {
      return { usable: false, reasonCode: "STEP_UP_NOT_YET_VALID" };
    }
    if (this.#activeRequestArtifacts(requestRecord.request, policy, at) === undefined) {
      return { usable: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" };
    }
    if (authorization.approvedByType !== PrincipalType.HUMAN) {
      return { usable: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    const approverStatus = this.#credentialAuthority.checkCredentialById(
      authorization.approverCredentialId,
      at,
      authorization.approvedBy,
      authorization.approvedByType,
    );
    if (!approverStatus.valid) {
      if (approverStatus.code === "CREDENTIAL_REVOKED") {
        return { usable: false, reasonCode: "APPROVER_CREDENTIAL_REVOKED" };
      }
      if (approverStatus.code === "CREDENTIAL_EXPIRED") {
        return { usable: false, reasonCode: "APPROVER_CREDENTIAL_EXPIRED" };
      }
      return { usable: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    const approverCredential = this.#credentialAuthority.getActiveCredentialById(
      authorization.approverCredentialId,
      at,
      authorization.approvedBy,
      authorization.approvedByType,
    );
    if (approverCredential === undefined) {
      return { usable: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    if (!approverCredential.capabilities.includes(authorization.requiredApproverCapability)) {
      return { usable: false, reasonCode: "APPROVER_CAPABILITY_MISSING" };
    }
    if (
      !approverCredential.allowedActions.includes("step-up:resolve") ||
      !approverCredential.allowedResourceIds.includes(authorization.resourceId)
    ) {
      return { usable: false, reasonCode: "APPROVER_SCOPE_MISSING" };
    }
    if (
      timestampMillis(at) >= timestampMillis(requestRecord.request.expiresAt) ||
      timestampMillis(at) >= timestampMillis(authorization.expiresAt)
    ) {
      return { usable: false, reasonCode: "STEP_UP_EXPIRED" };
    }
    if (this.#consumedAuthorizationIds.has(authorization.id)) {
      return { usable: false, reasonCode: "STEP_UP_AUTHORIZATION_CONSUMED" };
    }
    return { usable: true, reasonCode: "STEP_UP_AUTHORIZATION_USABLE" };
  }

  #activeDecisionArtifacts(
    decision: AccessDecision,
    policy: Policy,
    at: string,
  ): ActiveRequestArtifacts | undefined {
    if (!revalidateLiveDecisionAuthority({
      binding: decision as LiveDecisionAuthorityBinding,
      at,
      credentialAuthority: this.#credentialAuthority,
      ...(this.#delegationAuthority === undefined
        ? {}
        : { delegationAuthority: this.#delegationAuthority }),
    })) {
      return undefined;
    }
    const actingCredential = this.#credentialAuthority.getActiveCredentialById(
      decision.actingCredentialId,
      at,
      decision.subjectId,
      decision.subjectType,
    );
    if (actingCredential === undefined) return undefined;
    if (decision.authorityMode === "DIRECT") {
      if (
        actingCredential.scopeHash !== decision.effectiveScopeHash ||
        (decision.credentialId !== undefined && decision.credentialId !== actingCredential.id)
      ) {
        return undefined;
      }
      return { actingCredential };
    }
    if (decision.authorityMode !== "DELEGATED" || this.#delegationAuthority === undefined) {
      return undefined;
    }
    const delegation = this.#delegationAuthority.getActiveDelegationById(
      decision.delegationId,
      at,
    );
    if (
      delegation === undefined ||
      delegation.delegateId !== decision.subjectId ||
      delegation.delegateType !== decision.subjectType ||
      delegation.grantorId !== decision.grantorId ||
      delegation.grantorType !== decision.grantorType ||
      delegation.grantorCredentialId !== decision.grantorCredentialId ||
      delegation.id !== decision.delegationId ||
      delegation.delegationBindingHash !== decision.delegationBindingHash ||
      delegation.scopeHash !== decision.effectiveScopeHash ||
      delegation.policyId !== decision.policyId ||
      delegation.policyVersion !== decision.policyVersion
    ) {
      return undefined;
    }
    const grantorCredential = this.#credentialAuthority.getActiveCredentialById(
      decision.grantorCredentialId,
      at,
      decision.grantorId,
      decision.grantorType,
    );
    if (grantorCredential === undefined) return undefined;
    return { actingCredential, grantorCredential, delegation };
  }

  #activeRequestArtifacts(
    request: StepUpRequest,
    policy: Policy,
    at: string,
  ): ActiveRequestArtifacts | undefined {
    const binding: LiveDecisionAuthorityBinding = request.authorityMode === "DIRECT"
      ? {
        authorityMode: "DIRECT",
        subjectId: request.subjectId,
        subjectType: request.subjectType,
        actingCredentialId: request.actingCredentialId,
        effectiveScopeHash: request.effectiveScopeHash,
        action: request.action,
        actionSensitivity: request.actionSensitivity,
        resourceId: request.resourceId,
        policyId: request.policyId,
        policyVersion: request.policyVersion,
        outcome: "STEP_UP",
        reasonCode: "HUMAN_APPROVAL_REQUIRED",
        requiredApproverCapability: request.requiredApproverCapability,
        ...(request.credentialId === undefined ? {} : { credentialId: request.credentialId }),
      }
      : {
        authorityMode: "DELEGATED",
        subjectId: request.subjectId,
        subjectType: request.subjectType,
        actingCredentialId: request.actingCredentialId,
        effectiveScopeHash: request.effectiveScopeHash,
        action: request.action,
        actionSensitivity: request.actionSensitivity,
        resourceId: request.resourceId,
        policyId: request.policyId,
        policyVersion: request.policyVersion,
        outcome: "STEP_UP",
        reasonCode: "HUMAN_APPROVAL_REQUIRED",
        requiredApproverCapability: request.requiredApproverCapability,
        grantorId: request.grantorId,
        grantorType: request.grantorType,
        grantorCredentialId: request.grantorCredentialId,
        delegationId: request.delegationId,
        delegationBindingHash: request.delegationBindingHash,
      };
    if (!revalidateLiveDecisionAuthority({
      binding,
      at,
      credentialAuthority: this.#credentialAuthority,
      ...(this.#delegationAuthority === undefined
        ? {}
        : { delegationAuthority: this.#delegationAuthority }),
    })) {
      return undefined;
    }
    const actingCredential = this.#credentialAuthority.getActiveCredentialById(
      request.actingCredentialId,
      at,
      request.subjectId,
      request.subjectType,
    );
    if (actingCredential === undefined) return undefined;
    if (request.authorityMode === "DIRECT") {
      if (
        actingCredential.scopeHash !== request.effectiveScopeHash ||
        (request.credentialId !== undefined && request.credentialId !== actingCredential.id)
      ) {
        return undefined;
      }
      return { actingCredential };
    }
    if (this.#delegationAuthority === undefined) return undefined;
    const delegation = this.#delegationAuthority.getActiveDelegationById(
      request.delegationId,
      at,
    );
    if (
      delegation === undefined ||
      delegation.delegateId !== request.subjectId ||
      delegation.delegateType !== request.subjectType ||
      delegation.grantorId !== request.grantorId ||
      delegation.grantorType !== request.grantorType ||
      delegation.grantorCredentialId !== request.grantorCredentialId ||
      delegation.delegationBindingHash !== request.delegationBindingHash ||
      delegation.scopeHash !== request.effectiveScopeHash ||
      delegation.policyId !== request.policyId ||
      delegation.policyVersion !== request.policyVersion
    ) {
      return undefined;
    }
    const grantorCredential = this.#credentialAuthority.getActiveCredentialById(
      request.grantorCredentialId,
      at,
      request.grantorId,
      request.grantorType,
    );
    if (grantorCredential === undefined) return undefined;
    return { actingCredential, grantorCredential, delegation };
  }

  #validateExpectedBinding(
    record: Record<string, unknown>,
    authorityMode: AuthorityMode,
  ): StepUpAuthorizationBinding {
    if (record.authorityMode !== authorityMode) {
      throw new DomainValidationError("expected.authorityMode does not match authorization");
    }
    const common = {
      requestId: validateIdentifier(record.requestId, "expected.requestId"),
      authorityMode,
      subjectId: validateIdentifier(record.subjectId, "expected.subjectId"),
      subjectType: validatePrincipalType(record.subjectType, "expected.subjectType"),
      actingCredentialId: validateIdentifier(
        record.actingCredentialId,
        "expected.actingCredentialId",
      ),
      effectiveScopeHash: validateContextHash(
        record.effectiveScopeHash,
        "expected.effectiveScopeHash",
      ),
      action: validateAction(record.action, "expected.action"),
      actionSensitivity: validateActionSensitivity(
        record.actionSensitivity,
        "expected.actionSensitivity",
      ),
      resourceId: validateIdentifier(record.resourceId, "expected.resourceId"),
      contextHash: validateContextHash(record.contextHash, "expected.contextHash"),
      policyId: validateIdentifier(record.policyId, "expected.policyId"),
      policyVersion: validateContextHash(record.policyVersion, "expected.policyVersion"),
      requiredApproverCapability: validateCapability(
        record.requiredApproverCapability,
        "expected.requiredApproverCapability",
      ),
      approvedBy: validateIdentifier(record.approvedBy, "expected.approvedBy"),
      approvedByType: validatePrincipalType(record.approvedByType, "expected.approvedByType"),
      approverCredentialId: validateIdentifier(
        record.approverCredentialId,
        "expected.approverCredentialId",
      ),
    };
    if (authorityMode === "DIRECT") {
      if (record.credentialId === undefined) {
        return Object.freeze({ ...common, authorityMode: "DIRECT" });
      }
      return Object.freeze({
        ...common,
        authorityMode: "DIRECT",
        credentialId: validateIdentifier(record.credentialId, "expected.credentialId"),
      });
    }
    return Object.freeze({
      ...common,
      authorityMode: "DELEGATED",
      grantorId: validateIdentifier(record.grantorId, "expected.grantorId"),
      grantorType: validatePrincipalType(record.grantorType, "expected.grantorType"),
      grantorCredentialId: validateIdentifier(
        record.grantorCredentialId,
        "expected.grantorCredentialId",
      ),
      delegationId: validateIdentifier(record.delegationId, "expected.delegationId"),
      delegationBindingHash: validateContextHash(
        record.delegationBindingHash,
        "expected.delegationBindingHash",
      ),
    });
  }

  #matchesExpectedBinding(
    authorization: StepUpAuthorization,
    expected: StepUpAuthorizationBinding,
  ): boolean {
    if (
      authorization.requestId !== expected.requestId ||
      authorization.authorityMode !== expected.authorityMode ||
      authorization.subjectId !== expected.subjectId ||
      authorization.subjectType !== expected.subjectType ||
      authorization.actingCredentialId !== expected.actingCredentialId ||
      authorization.effectiveScopeHash !== expected.effectiveScopeHash ||
      authorization.action !== expected.action ||
      authorization.actionSensitivity !== expected.actionSensitivity ||
      authorization.resourceId !== expected.resourceId ||
      authorization.contextHash !== expected.contextHash ||
      authorization.policyId !== expected.policyId ||
      authorization.policyVersion !== expected.policyVersion ||
      authorization.requiredApproverCapability !== expected.requiredApproverCapability ||
      authorization.approvedBy !== expected.approvedBy ||
      authorization.approvedByType !== expected.approvedByType ||
      authorization.approverCredentialId !== expected.approverCredentialId
    ) {
      return false;
    }
    if (authorization.authorityMode === "DIRECT" && expected.authorityMode === "DIRECT") {
      return expected.credentialId === undefined ||
        expected.credentialId === authorization.credentialId;
    }
    return authorization.authorityMode === "DELEGATED" &&
      expected.authorityMode === "DELEGATED" &&
      authorization.grantorId === expected.grantorId &&
      authorization.grantorType === expected.grantorType &&
      authorization.grantorCredentialId === expected.grantorCredentialId &&
      authorization.delegationId === expected.delegationId &&
      authorization.delegationBindingHash === expected.delegationBindingHash;
  }
}
