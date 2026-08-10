import type {
  AccessDecision,
  Affiliation,
  AuthorityMode,
  BoundAccessDecision,
  CapabilityDelegation,
  Credential,
  DecisionLogEntry,
  DelegatedScopeView,
  EligibleActionStatus,
  OnboardingView,
  Principal,
  PrincipalType,
  ReasonCode,
  ReceiptExpectedBinding,
  ReceiptPayload,
  RequiredApprovalStatus,
  SignedReceipt,
  StepUpAuthorization,
  StepUpRequest,
  UnverifiedMetadata,
  VerificationStatus,
} from "./index.js";

export class InvalidProtocolResponse extends Error {
  constructor() {
    super("response does not match the zKYC reference protocol");
    this.name = "InvalidProtocolResponse";
  }
}

type JsonRecord = Record<string, unknown>;

const reasonCodes = new Set<ReasonCode>([
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
  "ACTION_OUTSIDE_CREDENTIAL_SCOPE",
  "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE",
  "DELEGATION_MALFORMED",
  "DELEGATION_UNKNOWN",
  "DELEGATION_NOT_YET_VALID",
  "DELEGATION_EXPIRED",
  "DELEGATION_REVOKED",
  "DELEGATION_POLICY_MISMATCH",
  "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
  "DELEGATION_GRANTOR_MISMATCH",
  "DELEGATION_DELEGATE_MISMATCH",
  "ACTION_OUTSIDE_DELEGATION_SCOPE",
  "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
  "INSUFFICIENT_DELEGATED_CAPABILITY",
  "INSUFFICIENT_CAPABILITY",
  "AFFILIATION_REQUIRED",
  "ACTION_NOT_PERMITTED",
]);

const delegatedBindingFields = [
  "grantorId",
  "grantorType",
  "grantorCredentialId",
  "delegationId",
  "delegationBindingHash",
] as const;

function invalid(): never {
  throw new InvalidProtocolResponse();
}

function record(value: unknown, allowed: readonly string[], required: readonly string[] = allowed): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const output = value as JsonRecord;
  const allowedSet = new Set(allowed);
  if (Object.keys(output).some((key) => !allowedSet.has(key))) invalid();
  if (required.some((key) => !Object.hasOwn(output, key))) invalid();
  return output;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) invalid();
  return value;
}

function identifier(value: unknown): string {
  const output = stringField(value);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(output)) invalid();
  return output;
}

function timestamp(value: unknown): string {
  const output = stringField(value);
  const parsed = new Date(output);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== output) invalid();
  return output;
}

function hash(value: unknown): string {
  const output = stringField(value);
  if (!/^sha256:[0-9a-f]{64}$/.test(output)) invalid();
  return output;
}

function booleanField(value: unknown): boolean {
  if (typeof value !== "boolean") invalid();
  return value;
}

function canonicalIdentifiers(value: unknown, requireNonEmpty = false): readonly string[] {
  if (!Array.isArray(value) || (requireNonEmpty && value.length === 0)) invalid();
  const output = value.map(identifier);
  if (new Set(output).size !== output.length) invalid();
  if (output.some((entry, index) => index > 0 && output[index - 1]! >= entry)) invalid();
  return output;
}

function affiliation(value: unknown): Affiliation {
  const item = record(value, ["organizationId", "role"]);
  return {
    organizationId: identifier(item.organizationId),
    role: identifier(item.role),
  };
}

function affiliations(value: unknown): readonly Affiliation[] {
  if (!Array.isArray(value)) invalid();
  const output = value.map(affiliation);
  const keys = output.map((entry) => `${entry.organizationId}\u0000${entry.role}`);
  if (new Set(keys).size !== keys.length) invalid();
  if (keys.some((entry, index) => index > 0 && keys[index - 1]! >= entry)) invalid();
  return output;
}

function principalType(value: unknown): PrincipalType {
  if (value !== "HUMAN" && value !== "ORGANIZATION" && value !== "AGENT") invalid();
  return value;
}

function principal(value: unknown): Principal {
  const item = record(value, ["id", "type", "affiliations"]);
  return {
    id: identifier(item.id),
    type: principalType(item.type),
    affiliations: affiliations(item.affiliations),
  };
}

function metadata(value: unknown): UnverifiedMetadata {
  const item = record(value, ["zkPassProofId", "contextualProofIds"], []);
  return {
    ...(item.zkPassProofId === undefined ? {} : { zkPassProofId: identifier(item.zkPassProofId) }),
    ...(item.contextualProofIds === undefined
      ? {}
      : { contextualProofIds: canonicalIdentifiers(item.contextualProofIds) }),
  };
}

function sensitivity(value: unknown): "ROUTINE" | "SENSITIVE" | "CRITICAL" {
  if (value !== "ROUTINE" && value !== "SENSITIVE" && value !== "CRITICAL") invalid();
  return value;
}

function outcome(value: unknown): "ALLOW" | "DENY" | "STEP_UP" {
  if (value !== "ALLOW" && value !== "DENY" && value !== "STEP_UP") invalid();
  return value;
}

function reasonCode(value: unknown): ReasonCode {
  if (typeof value !== "string" || !reasonCodes.has(value as ReasonCode)) invalid();
  return value as ReasonCode;
}

function protocolReasonCode(value: unknown): string {
  const output = stringField(value);
  if (!/^[A-Z][A-Z0-9_]*$/.test(output)) invalid();
  return output;
}

function authorityMode(value: unknown): AuthorityMode {
  if (value !== "DIRECT" && value !== "DELEGATED") invalid();
  return value;
}

function stepUpStatus(value: unknown): "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" {
  if (value !== "PENDING" && value !== "APPROVED" && value !== "REJECTED" && value !== "EXPIRED") {
    invalid();
  }
  return value;
}

function eligibleActionStatus(value: unknown): EligibleActionStatus {
  if (value !== "ELIGIBLE" && value !== "APPROVAL_REQUIRED" && value !== "INELIGIBLE") invalid();
  return value;
}

function requiredApprovalStatus(value: unknown): RequiredApprovalStatus {
  if (
    value !== "NOT_REQUIRED" &&
    value !== "PENDING" &&
    value !== "APPROVED" &&
    value !== "REJECTED" &&
    value !== "EXPIRED"
  ) invalid();
  return value;
}

function receiptState(value: unknown): "NOT_ISSUED" | "UNCONSUMED" | "CONSUMED" | "REJECTED" {
  if (value !== "NOT_ISSUED" && value !== "UNCONSUMED" && value !== "CONSUMED" && value !== "REJECTED") {
    invalid();
  }
  return value;
}

function assertDecisionCapability(
  decision: "ALLOW" | "DENY" | "STEP_UP",
  item: JsonRecord,
): string | undefined {
  if (decision === "STEP_UP") {
    if (!Object.hasOwn(item, "requiredApproverCapability")) invalid();
    return identifier(item.requiredApproverCapability);
  }
  if (Object.hasOwn(item, "requiredApproverCapability")) invalid();
  return undefined;
}

function validateCredentialValue(value: unknown): Credential {
  const item = record(
    value,
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
    ],
  );
  if (item.version !== 2) invalid();
  const issuedAt = timestamp(item.issuedAt);
  const expiresAt = timestamp(item.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) invalid();
  return {
    version: 2,
    id: identifier(item.id),
    issuerId: identifier(item.issuerId),
    principalId: identifier(item.principalId),
    principalType: principalType(item.principalType),
    affiliations: affiliations(item.affiliations),
    capabilities: canonicalIdentifiers(item.capabilities),
    allowedActions: canonicalIdentifiers(item.allowedActions),
    allowedResourceIds: canonicalIdentifiers(item.allowedResourceIds),
    issuedAt,
    expiresAt,
    scopeHash: hash(item.scopeHash),
    ...(item.unverifiedMetadata === undefined
      ? {}
      : { unverifiedMetadata: metadata(item.unverifiedMetadata) }),
  };
}

function validateDelegationValue(value: unknown): CapabilityDelegation {
  const item = record(value, [
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
  ]);
  if (item.version !== 1) invalid();
  const issuedAt = timestamp(item.issuedAt);
  const expiresAt = timestamp(item.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) invalid();
  return {
    version: 1,
    id: identifier(item.id),
    issuerId: identifier(item.issuerId),
    grantorCredentialId: identifier(item.grantorCredentialId),
    grantorId: identifier(item.grantorId),
    grantorType: principalType(item.grantorType),
    delegateId: identifier(item.delegateId),
    delegateType: principalType(item.delegateType),
    policyId: identifier(item.policyId),
    policyVersion: hash(item.policyVersion),
    capabilities: canonicalIdentifiers(item.capabilities, true),
    allowedActions: canonicalIdentifiers(item.allowedActions, true),
    allowedResourceIds: canonicalIdentifiers(item.allowedResourceIds, true),
    issuedAt,
    expiresAt,
    scopeHash: hash(item.scopeHash),
    delegationBindingHash: hash(item.delegationBindingHash),
  };
}

const decisionCoreFields = [
  "version",
  "outcome",
  "reasonCode",
  "authorityMode",
  "subjectId",
  "subjectType",
  "action",
  "actionSensitivity",
  "resourceId",
  "contextHash",
  "policyId",
  "policyVersion",
  "decidedAt",
] as const;

const decisionBindingFields = ["actingCredentialId", "effectiveScopeHash"] as const;
const decisionCommonFields = [...decisionCoreFields, ...decisionBindingFields] as const;

function validateDecisionValue(value: unknown): AccessDecision {
  const initial = record(value, [
    ...decisionCommonFields,
    "credentialId",
    ...delegatedBindingFields,
    "requiredApproverCapability",
    "unverifiedMetadata",
  ], decisionCoreFields);
  const mode = authorityMode(initial.authorityMode);
  const decisionOutcome = outcome(initial.outcome);
  const decisionReason = reasonCode(initial.reasonCode);
  const isUnboundDirectDenial = mode === "DIRECT" &&
    !Object.hasOwn(initial, "actingCredentialId") &&
    !Object.hasOwn(initial, "effectiveScopeHash") &&
    !Object.hasOwn(initial, "credentialId");
  if (isUnboundDirectDenial) {
    record(value, decisionCoreFields);
    if (decisionOutcome !== "DENY" || decisionReason !== "CREDENTIAL_MISSING") invalid();
    if (initial.version !== 2) invalid();
    return {
      version: 2,
      outcome: "DENY",
      reasonCode: "CREDENTIAL_MISSING",
      authorityMode: "DIRECT",
      subjectId: identifier(initial.subjectId),
      subjectType: principalType(initial.subjectType),
      action: identifier(initial.action),
      actionSensitivity: sensitivity(initial.actionSensitivity),
      resourceId: identifier(initial.resourceId),
      contextHash: hash(initial.contextHash),
      policyId: identifier(initial.policyId),
      policyVersion: hash(initial.policyVersion),
      decidedAt: timestamp(initial.decidedAt),
    };
  }
  record(
    value,
    mode === "DIRECT"
      ? [...decisionCommonFields, "credentialId", "requiredApproverCapability", "unverifiedMetadata"]
      : [
        ...decisionCommonFields,
        ...delegatedBindingFields,
        "requiredApproverCapability",
        "unverifiedMetadata",
      ],
    mode === "DIRECT" ? decisionCommonFields : [...decisionCommonFields, ...delegatedBindingFields],
  );
  if (initial.version !== 2) invalid();
  if (decisionOutcome === "ALLOW" && decisionReason !== "POLICY_ALLOW") invalid();
  if (decisionOutcome === "STEP_UP" && decisionReason !== "HUMAN_APPROVAL_REQUIRED") invalid();
  if (
    decisionOutcome === "DENY" &&
    (decisionReason === "POLICY_ALLOW" || decisionReason === "HUMAN_APPROVAL_REQUIRED")
  ) invalid();
  const actingCredentialId = identifier(initial.actingCredentialId);
  const common = {
    version: 2 as const,
    outcome: decisionOutcome,
    reasonCode: decisionReason,
    authorityMode: mode,
    subjectId: identifier(initial.subjectId),
    subjectType: principalType(initial.subjectType),
    actingCredentialId,
    effectiveScopeHash: hash(initial.effectiveScopeHash),
    action: identifier(initial.action),
    actionSensitivity: sensitivity(initial.actionSensitivity),
    resourceId: identifier(initial.resourceId),
    contextHash: hash(initial.contextHash),
    policyId: identifier(initial.policyId),
    policyVersion: hash(initial.policyVersion),
    decidedAt: timestamp(initial.decidedAt),
    ...(assertDecisionCapability(decisionOutcome, initial) === undefined
      ? {}
      : { requiredApproverCapability: identifier(initial.requiredApproverCapability) }),
    ...(initial.unverifiedMetadata === undefined
      ? {}
      : { unverifiedMetadata: metadata(initial.unverifiedMetadata) }),
  };
  if (mode === "DIRECT") {
    if (initial.credentialId === undefined) return { ...common, authorityMode: "DIRECT" };
    const credentialId = identifier(initial.credentialId);
    if (credentialId !== actingCredentialId) invalid();
    return { ...common, authorityMode: "DIRECT", credentialId };
  }
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: identifier(initial.grantorId),
    grantorType: principalType(initial.grantorType),
    grantorCredentialId: identifier(initial.grantorCredentialId),
    delegationId: identifier(initial.delegationId),
    delegationBindingHash: hash(initial.delegationBindingHash),
  };
}

const receiptCommonFields = [
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
  "decision",
  "reasonCode",
] as const;

function validateReceiptBinding(
  value: unknown,
  directCredentialRequired: boolean,
): ReceiptExpectedBinding {
  const initial = record(value, [
    ...receiptCommonFields,
    "credentialId",
    ...delegatedBindingFields,
    "requiredApproverCapability",
  ], receiptCommonFields);
  const mode = authorityMode(initial.authorityMode);
  const required = mode === "DIRECT"
    ? directCredentialRequired ? [...receiptCommonFields, "credentialId"] : receiptCommonFields
    : [...receiptCommonFields, ...delegatedBindingFields];
  record(
    value,
    mode === "DIRECT"
      ? [...receiptCommonFields, "credentialId", "requiredApproverCapability"]
      : [...receiptCommonFields, ...delegatedBindingFields, "requiredApproverCapability"],
    required,
  );
  const decision = outcome(initial.decision);
  const reason = reasonCode(initial.reasonCode);
  if (decision === "ALLOW" && reason !== "POLICY_ALLOW") invalid();
  if (decision === "STEP_UP" && reason !== "HUMAN_APPROVAL_REQUIRED") invalid();
  if (decision === "DENY" && (reason === "POLICY_ALLOW" || reason === "HUMAN_APPROVAL_REQUIRED")) {
    invalid();
  }
  const approverCapability = assertDecisionCapability(decision, initial);
  const actingCredentialId = identifier(initial.actingCredentialId);
  const common = {
    authorityMode: mode,
    subjectId: identifier(initial.subjectId),
    subjectType: principalType(initial.subjectType),
    actingCredentialId,
    effectiveScopeHash: hash(initial.effectiveScopeHash),
    action: identifier(initial.action),
    actionSensitivity: sensitivity(initial.actionSensitivity),
    resourceId: identifier(initial.resourceId),
    contextHash: hash(initial.contextHash),
    policyId: identifier(initial.policyId),
    policyVersion: hash(initial.policyVersion),
    decision,
    reasonCode: reason,
    ...(approverCapability === undefined ? {} : { requiredApproverCapability: approverCapability }),
  };
  if (mode === "DIRECT") {
    const credentialId = identifier(initial.credentialId);
    if (credentialId !== actingCredentialId) invalid();
    return { ...common, authorityMode: "DIRECT", credentialId };
  }
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: identifier(initial.grantorId),
    grantorType: principalType(initial.grantorType),
    grantorCredentialId: identifier(initial.grantorCredentialId),
    delegationId: identifier(initial.delegationId),
    delegationBindingHash: hash(initial.delegationBindingHash),
  };
}

function validateReceiptPayloadValue(value: unknown): ReceiptPayload {
  const initial = record(value, [
    "version",
    ...receiptCommonFields,
    "credentialId",
    ...delegatedBindingFields,
    "requiredApproverCapability",
    "nonce",
    "decidedAt",
    "issuedAt",
    "expiresAt",
  ], ["version", ...receiptCommonFields, "nonce", "decidedAt", "issuedAt", "expiresAt"]);
  if (initial.version !== 2) invalid();
  const bindingFields = Object.fromEntries(
    [
      ...receiptCommonFields,
      "credentialId",
      ...delegatedBindingFields,
      "requiredApproverCapability",
    ].filter((field) => Object.hasOwn(initial, field)).map((field) => [field, initial[field]]),
  );
  const binding = validateReceiptBinding(bindingFields, true);
  const decidedAt = timestamp(initial.decidedAt);
  const issuedAt = timestamp(initial.issuedAt);
  const expiresAt = timestamp(initial.expiresAt);
  if (Date.parse(decidedAt) > Date.parse(issuedAt) || Date.parse(issuedAt) >= Date.parse(expiresAt)) {
    invalid();
  }
  return {
    version: 2,
    ...binding,
    nonce: identifier(initial.nonce),
    decidedAt,
    issuedAt,
    expiresAt,
  };
}

function validateReceiptValue(value: unknown): SignedReceipt {
  const item = record(value, ["algorithm", "payload", "signature"]);
  if (item.algorithm !== "HMAC-SHA256") invalid();
  const signature = stringField(item.signature);
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) invalid();
  return {
    algorithm: "HMAC-SHA256",
    payload: validateReceiptPayloadValue(item.payload),
    signature,
  };
}

const stepUpRequestCommonFields = [
  "version",
  "id",
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
  "requestedAt",
  "expiresAt",
  "status",
] as const;

function validateStepUpRequestValue(value: unknown): StepUpRequest {
  const initial = record(value, [
    ...stepUpRequestCommonFields,
    "credentialId",
    ...delegatedBindingFields,
  ], stepUpRequestCommonFields);
  const mode = authorityMode(initial.authorityMode);
  record(
    value,
    mode === "DIRECT"
      ? [...stepUpRequestCommonFields, "credentialId"]
      : [...stepUpRequestCommonFields, ...delegatedBindingFields],
    mode === "DIRECT"
      ? stepUpRequestCommonFields
      : [...stepUpRequestCommonFields, ...delegatedBindingFields],
  );
  if (initial.version !== 2) invalid();
  const requestedAt = timestamp(initial.requestedAt);
  const expiresAt = timestamp(initial.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(requestedAt)) invalid();
  const status = stepUpStatus(initial.status);
  const actingCredentialId = identifier(initial.actingCredentialId);
  const common = {
    version: 2 as const,
    id: identifier(initial.id),
    authorityMode: mode,
    subjectId: identifier(initial.subjectId),
    subjectType: principalType(initial.subjectType),
    actingCredentialId,
    effectiveScopeHash: hash(initial.effectiveScopeHash),
    action: identifier(initial.action),
    actionSensitivity: sensitivity(initial.actionSensitivity),
    resourceId: identifier(initial.resourceId),
    contextHash: hash(initial.contextHash),
    policyId: identifier(initial.policyId),
    policyVersion: hash(initial.policyVersion),
    requiredApproverCapability: identifier(initial.requiredApproverCapability),
    requestedAt,
    expiresAt,
    status,
  };
  if (mode === "DIRECT") {
    if (initial.credentialId === undefined) return { ...common, authorityMode: "DIRECT" };
    const credentialId = identifier(initial.credentialId);
    if (credentialId !== actingCredentialId) invalid();
    return { ...common, authorityMode: "DIRECT", credentialId };
  }
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: identifier(initial.grantorId),
    grantorType: principalType(initial.grantorType),
    grantorCredentialId: identifier(initial.grantorCredentialId),
    delegationId: identifier(initial.delegationId),
    delegationBindingHash: hash(initial.delegationBindingHash),
  };
}

const authorizationCommonFields = [
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

function validateAuthorizationValue(value: unknown): StepUpAuthorization {
  const initial = record(value, [
    ...authorizationCommonFields,
    "credentialId",
    ...delegatedBindingFields,
  ], authorizationCommonFields);
  const mode = authorityMode(initial.authorityMode);
  record(
    value,
    mode === "DIRECT"
      ? [...authorizationCommonFields, "credentialId"]
      : [...authorizationCommonFields, ...delegatedBindingFields],
    mode === "DIRECT"
      ? authorizationCommonFields
      : [...authorizationCommonFields, ...delegatedBindingFields],
  );
  if (initial.version !== 2) invalid();
  const issuedAt = timestamp(initial.issuedAt);
  const expiresAt = timestamp(initial.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) invalid();
  const actingCredentialId = identifier(initial.actingCredentialId);
  const approvedByType = principalType(initial.approvedByType);
  if (approvedByType !== "HUMAN") invalid();
  const common = {
    version: 2 as const,
    id: identifier(initial.id),
    requestId: identifier(initial.requestId),
    authorityMode: mode,
    subjectId: identifier(initial.subjectId),
    subjectType: principalType(initial.subjectType),
    actingCredentialId,
    effectiveScopeHash: hash(initial.effectiveScopeHash),
    action: identifier(initial.action),
    actionSensitivity: sensitivity(initial.actionSensitivity),
    resourceId: identifier(initial.resourceId),
    contextHash: hash(initial.contextHash),
    policyId: identifier(initial.policyId),
    policyVersion: hash(initial.policyVersion),
    requiredApproverCapability: identifier(initial.requiredApproverCapability),
    approvedBy: identifier(initial.approvedBy),
    approvedByType,
    approverCredentialId: identifier(initial.approverCredentialId),
    issuedAt,
    expiresAt,
  };
  if (mode === "DIRECT") {
    if (initial.credentialId === undefined) return { ...common, authorityMode: "DIRECT" };
    const credentialId = identifier(initial.credentialId);
    if (credentialId !== actingCredentialId) invalid();
    return { ...common, authorityMode: "DIRECT", credentialId };
  }
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: identifier(initial.grantorId),
    grantorType: principalType(initial.grantorType),
    grantorCredentialId: identifier(initial.grantorCredentialId),
    delegationId: identifier(initial.delegationId),
    delegationBindingHash: hash(initial.delegationBindingHash),
  };
}

function assertReceiptMatchesDecision(receipt: SignedReceipt, decision: AccessDecision): void {
  if (decision.actingCredentialId === undefined || decision.effectiveScopeHash === undefined) invalid();
  assertReceiptMatchesBoundDecision(receipt, decision as BoundAccessDecision);
}

function assertReceiptMatchesBoundDecision(receipt: SignedReceipt, decision: BoundAccessDecision): void {
  const payload = receipt.payload;
  if (
    payload.authorityMode !== decision.authorityMode ||
    payload.subjectId !== decision.subjectId ||
    payload.subjectType !== decision.subjectType ||
    payload.actingCredentialId !== decision.actingCredentialId ||
    payload.effectiveScopeHash !== decision.effectiveScopeHash ||
    payload.action !== decision.action ||
    payload.actionSensitivity !== decision.actionSensitivity ||
    payload.resourceId !== decision.resourceId ||
    payload.contextHash !== decision.contextHash ||
    payload.policyId !== decision.policyId ||
    payload.policyVersion !== decision.policyVersion ||
    payload.decision !== decision.outcome ||
    payload.reasonCode !== decision.reasonCode ||
    payload.requiredApproverCapability !== decision.requiredApproverCapability
  ) invalid();
  if (payload.authorityMode === "DIRECT" && decision.authorityMode === "DIRECT") {
    if (payload.credentialId !== decision.actingCredentialId) invalid();
    if (decision.credentialId !== undefined && payload.credentialId !== decision.credentialId) invalid();
    return;
  }
  if (payload.authorityMode !== "DELEGATED" || decision.authorityMode !== "DELEGATED") invalid();
  if (
    payload.grantorId !== decision.grantorId ||
    payload.grantorType !== decision.grantorType ||
    payload.grantorCredentialId !== decision.grantorCredentialId ||
    payload.delegationId !== decision.delegationId ||
    payload.delegationBindingHash !== decision.delegationBindingHash
  ) invalid();
}

export function validateHealthResponse(value: unknown) {
  const item = record(value, ["ok", "service", "version", "state"]);
  if (
    item.ok !== true ||
    item.service !== "zkyc-core-api-reference" ||
    item.version !== "0.3.0" ||
    item.state !== "in-memory-reference-only"
  ) invalid();
  return {
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.3.0",
    state: "in-memory-reference-only",
  } as const;
}

export function validateCredentialResponse(value: unknown): { readonly credential: Credential } {
  const item = record(value, ["credential"]);
  return { credential: validateCredentialValue(item.credential) };
}

export function validateDelegationResponse(
  value: unknown,
): { readonly delegation: CapabilityDelegation } {
  const item = record(value, ["delegation"]);
  return { delegation: validateDelegationValue(item.delegation) };
}

export function validateRevocationResponse(value: unknown): { readonly revoked: boolean } {
  const item = record(value, ["revoked"]);
  return { revoked: booleanField(item.revoked) };
}

export function validateEvaluationResponse(
  value: unknown,
): { readonly logId: string; readonly decision: AccessDecision; readonly receipt?: SignedReceipt } {
  const item = record(value, ["logId", "decision", "receipt"], ["logId", "decision"]);
  const logId = identifier(item.logId);
  const decision = validateDecisionValue(item.decision);
  if (item.receipt === undefined) return { logId, decision };
  const receipt = validateReceiptValue(item.receipt);
  assertReceiptMatchesDecision(receipt, decision);
  return { logId, decision, receipt };
}

export function validateStepUpRequestResponse(
  value: unknown,
): { readonly decisionLogId: string; readonly request: StepUpRequest } {
  const item = record(value, ["decisionLogId", "request"]);
  return {
    decisionLogId: identifier(item.decisionLogId),
    request: validateStepUpRequestValue(item.request),
  };
}

const stepUpFailureCodes = new Set([
  "STEP_UP_NOT_FOUND",
  "STEP_UP_EXPIRED",
  "STEP_UP_ALREADY_RESOLVED",
  "STEP_UP_REJECTED",
  "SUBJECT_AUTHORITY_INVALID",
  "APPROVER_CREDENTIAL_INVALID",
  "APPROVER_CAPABILITY_MISSING",
  "APPROVER_SCOPE_MISSING",
  "INVALID_INPUT",
]);

export function validateResolutionResponse(value: unknown):
  | { readonly ok: true; readonly authorization: StepUpAuthorization }
  | { readonly ok: false; readonly reasonCode: string } {
  const item = record(value, ["ok", "authorization", "reasonCode"], ["ok"]);
  if (item.ok === true) {
    if (item.authorization === undefined || item.reasonCode !== undefined) invalid();
    return { ok: true, authorization: validateAuthorizationValue(item.authorization) };
  }
  if (item.ok === false) {
    if (item.authorization !== undefined || !stepUpFailureCodes.has(String(item.reasonCode))) invalid();
    return { ok: false, reasonCode: String(item.reasonCode) };
  }
  return invalid();
}

export function validateAuthorizationConsumeResponse(
  value: unknown,
): { readonly authorized: boolean } {
  const item = record(value, ["authorized"]);
  return { authorized: booleanField(item.authorized) };
}

const receiptVerificationCodes = new Set([
  "RECEIPT_VALID",
  "RECEIPT_MALFORMED",
  "RECEIPT_SIGNATURE_INVALID",
  "RECEIPT_NOT_YET_VALID",
  "RECEIPT_EXPIRED",
  "RECEIPT_BINDING_MISMATCH",
  "RECEIPT_NOT_AUTHORIZING",
  "RECEIPT_CREDENTIAL_INVALID",
  "RECEIPT_AUTHORITY_INVALID",
  "RECEIPT_REPLAYED",
]);

export function validateReceiptConsumeResponse(
  value: unknown,
): { readonly valid: boolean; readonly reasonCode: string } {
  const item = record(value, ["valid", "reasonCode"]);
  if (!receiptVerificationCodes.has(String(item.reasonCode))) invalid();
  return { valid: booleanField(item.valid), reasonCode: String(item.reasonCode) };
}

function validateLogEntry(value: unknown): DecisionLogEntry {
  const item = record(
    value,
    ["id", "recordedAt", "principal", "decision", "receipt"],
    ["id", "recordedAt", "principal", "decision"],
  );
  const decision = validateDecisionValue(item.decision);
  const retainedPrincipal = principal(item.principal);
  if (
    retainedPrincipal.id !== decision.subjectId ||
    retainedPrincipal.type !== decision.subjectType
  ) invalid();
  const common = {
    id: identifier(item.id),
    recordedAt: timestamp(item.recordedAt),
    principal: retainedPrincipal,
    decision,
  };
  if (item.receipt === undefined) return common;
  const summary = record(item.receipt, ["algorithm", "payload", "signatureHash"]);
  if (summary.algorithm !== "HMAC-SHA256") invalid();
  const payload = validateReceiptPayloadValue(summary.payload);
  assertReceiptMatchesDecision(
    { algorithm: "HMAC-SHA256", payload, signature: "A".repeat(43) },
    decision,
  );
  return {
    ...common,
    receipt: {
      algorithm: "HMAC-SHA256",
      payload,
      signatureHash: hash(summary.signatureHash),
    },
  };
}

function verificationStatus(value: unknown): VerificationStatus {
  if (value !== "ACTIVE" && value !== "REVOKED" && value !== "EXPIRED" && value !== "INVALID") {
    invalid();
  }
  return value;
}

function delegatedScope(value: unknown): DelegatedScopeView {
  const item = record(value, [
    "delegationId",
    "grantorId",
    "grantorType",
    "capabilities",
    "allowedActions",
    "allowedResourceIds",
    "status",
  ]);
  return {
    delegationId: identifier(item.delegationId),
    grantorId: identifier(item.grantorId),
    grantorType: principalType(item.grantorType),
    capabilities: canonicalIdentifiers(item.capabilities, true),
    allowedActions: canonicalIdentifiers(item.allowedActions, true),
    allowedResourceIds: canonicalIdentifiers(item.allowedResourceIds, true),
    status: verificationStatus(item.status),
  };
}

export function validateOnboardingView(value: unknown): OnboardingView {
  const item = record(value, [
    "version",
    "referenceOnly",
    "decisionLogId",
    "verificationStatus",
    "principal",
    "authorityMode",
    "delegatedScope",
    "eligibleActions",
    "requiredApproval",
    "receipt",
    "policyId",
    "policyVersion",
  ]);
  if (item.version !== 1 || item.referenceOnly !== true) invalid();
  const mode = authorityMode(item.authorityMode);
  if (mode === "DIRECT" && item.delegatedScope !== null) invalid();
  if (mode === "DELEGATED" && item.delegatedScope === null) invalid();
  if (!Array.isArray(item.eligibleActions) || item.eligibleActions.length === 0) invalid();
  const eligibleActions = item.eligibleActions.map((value) => {
    const action = record(value, ["action", "resourceId", "status", "reasonCode"]);
    return {
      action: identifier(action.action),
      resourceId: identifier(action.resourceId),
      status: eligibleActionStatus(action.status),
      reasonCode: protocolReasonCode(action.reasonCode),
    };
  });
  const approval = record(item.requiredApproval, ["status", "requestId"], ["status"]);
  const approvalStatus = requiredApprovalStatus(approval.status);
  if (approvalStatus === "NOT_REQUIRED" && approval.requestId !== undefined) invalid();
  if (
    approvalStatus !== "NOT_REQUIRED" &&
    approvalStatus !== "PENDING" &&
    approval.requestId === undefined
  ) invalid();
  const requiredApproval = {
    status: approvalStatus,
    ...(approval.requestId === undefined ? {} : { requestId: identifier(approval.requestId) }),
  };
  const receipt = record(item.receipt, ["status"]);
  const retainedReceiptStatus = receiptState(receipt.status);
  return {
    version: 1,
    referenceOnly: true,
    decisionLogId: identifier(item.decisionLogId),
    verificationStatus: verificationStatus(item.verificationStatus),
    principal: principal(item.principal),
    authorityMode: mode,
    delegatedScope: item.delegatedScope === null ? null : delegatedScope(item.delegatedScope),
    eligibleActions,
    requiredApproval,
    receipt: { status: retainedReceiptStatus },
    policyId: identifier(item.policyId),
    policyVersion: hash(item.policyVersion),
  };
}

export function validateDecisionLogResponse(
  value: unknown,
): { readonly referenceOnly: true; readonly entries: readonly DecisionLogEntry[] } {
  const item = record(value, ["referenceOnly", "entries"]);
  if (item.referenceOnly !== true || !Array.isArray(item.entries)) invalid();
  return { referenceOnly: true, entries: item.entries.map(validateLogEntry) };
}
