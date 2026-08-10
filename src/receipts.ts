import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJson, sha256Version } from "./canonical.js";
import { CredentialAuthority, type Credential } from "./credentials.js";
import { DelegationAuthority, type CapabilityDelegation } from "./delegations.js";
import {
  DECISION_OUTCOMES,
  REASON_CODES,
  DomainValidationError,
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
  type ActionSensitivity,
  type DecisionOutcome,
  type PrincipalType,
  type ReasonCode,
} from "./domain.js";
import {
  revalidateLiveDecisionAuthority,
  type AuthorityMode,
  type LiveDecisionAuthorityBinding,
} from "./evaluation.js";
import type { AtomicNonceStore } from "./nonce.js";


interface CommonReceiptPayload {
  readonly version: 2;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly decision: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly requiredApproverCapability?: string;
  readonly nonce: string;
  readonly decidedAt: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface DirectReceiptPayload extends CommonReceiptPayload {
  readonly authorityMode: "DIRECT";
  /** @deprecated Compatibility alias. When present it equals actingCredentialId. */
  readonly credentialId?: string;
}

export interface DelegatedReceiptPayload extends CommonReceiptPayload {
  readonly authorityMode: "DELEGATED";
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type ReceiptPayload = DirectReceiptPayload | DelegatedReceiptPayload;

export interface SignedReceipt {
  readonly algorithm: "HMAC-SHA256";
  readonly payload: ReceiptPayload;
  readonly signature: string;
}

export type ReceiptVerificationCode =
  | "RECEIPT_VALID"
  | "RECEIPT_MALFORMED"
  | "RECEIPT_SIGNATURE_INVALID"
  | "RECEIPT_NOT_YET_VALID"
  | "RECEIPT_EXPIRED"
  | "RECEIPT_BINDING_MISMATCH"
  | "RECEIPT_NOT_AUTHORIZING"
  | "RECEIPT_CREDENTIAL_INVALID"
  | "RECEIPT_AUTHORITY_INVALID"
  | "RECEIPT_REPLAYED";

export interface ReceiptVerification {
  readonly valid: boolean;
  readonly reasonCode: ReceiptVerificationCode;
}

interface CommonReceiptExpectedBinding {
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly decision: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly requiredApproverCapability?: string;
}

export interface DirectReceiptExpectedBinding extends CommonReceiptExpectedBinding {
  readonly authorityMode: "DIRECT";
  /** @deprecated Compatibility alias. When present it equals actingCredentialId. */
  readonly credentialId?: string;
}

export interface DelegatedReceiptExpectedBinding extends CommonReceiptExpectedBinding {
  readonly authorityMode: "DELEGATED";
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type ReceiptExpectedBinding =
  | DirectReceiptExpectedBinding
  | DelegatedReceiptExpectedBinding;

export interface ReceiptInspectionBinding {
  readonly authorityMode?: AuthorityMode;
  readonly subjectId?: string;
  readonly subjectType?: PrincipalType;
  readonly actingCredentialId?: string;
  readonly effectiveScopeHash?: string;
  readonly action?: string;
  readonly actionSensitivity?: ActionSensitivity;
  readonly resourceId?: string;
  readonly contextHash?: string;
  readonly policyId?: string;
  readonly policyVersion?: string;
  readonly credentialId?: string;
  readonly grantorId?: string;
  readonly grantorType?: PrincipalType;
  readonly grantorCredentialId?: string;
  readonly delegationId?: string;
  readonly delegationBindingHash?: string;
  readonly decision?: DecisionOutcome;
  readonly reasonCode?: ReasonCode;
  readonly requiredApproverCapability?: string;
}

export interface ReceiptAuthorityConfiguration {
  readonly credentialAuthority: CredentialAuthority;
  readonly delegationAuthority?: DelegationAuthority;
}

export interface ReceiptConsumptionOptions {
  readonly at: string;
  readonly expected: ReceiptExpectedBinding;
  readonly delegationAuthority?: DelegationAuthority;
}

const commonBindingFields = [
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

const directOnlyFields = ["credentialId"] as const;
const delegatedOnlyFields = [
  "grantorId",
  "grantorType",
  "grantorCredentialId",
  "delegationId",
  "delegationBindingHash",
] as const;
const conditionalBindingFields = ["requiredApproverCapability"] as const;
const allBindingFields = [
  ...commonBindingFields,
  ...directOnlyFields,
  ...delegatedOnlyFields,
  ...conditionalBindingFields,
] as const;
const payloadTimeFields = ["nonce", "decidedAt", "issuedAt", "expiresAt"] as const;

function validateKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength < 32) {
    throw new DomainValidationError("receipt HMAC key must contain at least 32 bytes");
  }
}

function requireOwnFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  if (fields.some((field) => !Object.hasOwn(record, field))) {
    throw new DomainValidationError(`${label} must include every required field`);
  }
}

function validateAuthorityMode(value: unknown, label: string): AuthorityMode {
  if (value !== "DIRECT" && value !== "DELEGATED") {
    throw new DomainValidationError(`${label} is unsupported`);
  }
  return value;
}

function validateDecisionReason(decision: DecisionOutcome, reasonCode: ReasonCode): void {
  if (decision === "ALLOW" && reasonCode !== "POLICY_ALLOW") {
    throw new DomainValidationError("ALLOW receipts must use POLICY_ALLOW");
  }
  if (decision === "STEP_UP" && reasonCode !== "HUMAN_APPROVAL_REQUIRED") {
    throw new DomainValidationError("STEP_UP receipts must use HUMAN_APPROVAL_REQUIRED");
  }
  if (decision === "DENY" && (reasonCode === "POLICY_ALLOW" || reasonCode === "HUMAN_APPROVAL_REQUIRED")) {
    throw new DomainValidationError("DENY receipts must use a denial reason");
  }
}

function validateDecision(value: unknown, label: string): DecisionOutcome {
  if (!DECISION_OUTCOMES.includes(value as DecisionOutcome)) {
    throw new DomainValidationError(`${label} is unsupported`);
  }
  return value as DecisionOutcome;
}

function validateReason(value: unknown, label: string): ReasonCode {
  if (!REASON_CODES.includes(value as ReasonCode)) {
    throw new DomainValidationError(`${label} is unsupported`);
  }
  return value as ReasonCode;
}

function validateDecisionSpecificFields(
  record: Record<string, unknown>,
  decision: DecisionOutcome,
  label: string,
): string | undefined {
  const hasApproverCapability = Object.hasOwn(record, "requiredApproverCapability");
  if (decision === "STEP_UP") {
    if (!hasApproverCapability) {
      throw new DomainValidationError(`${label} STEP_UP must include requiredApproverCapability`);
    }
    return validateCapability(
      record.requiredApproverCapability,
      `${label} requiredApproverCapability`,
    );
  }
  if (hasApproverCapability) {
    throw new DomainValidationError(`${label} ALLOW/DENY must not include requiredApproverCapability`);
  }
  return undefined;
}

function validateBindingRecord(
  value: unknown,
  label: string,
): ReceiptExpectedBinding {
  const record = requireRecord(value, label);
  rejectUnknownKeys(record, allBindingFields, label);
  requireOwnFields(record, commonBindingFields, label);
  const authorityMode = validateAuthorityMode(record.authorityMode, `${label} authorityMode`);
  if (authorityMode === "DIRECT") {
    requireOwnFields(record, commonBindingFields, label);
    if (delegatedOnlyFields.some((field) => Object.hasOwn(record, field))) {
      throw new DomainValidationError(`${label} DIRECT must not include delegated fields`);
    }
  } else {
    requireOwnFields(record, delegatedOnlyFields, label);
    if (Object.hasOwn(record, "credentialId")) {
      throw new DomainValidationError(`${label} DELEGATED must not include credentialId`);
    }
  }
  const decision = validateDecision(record.decision, `${label} decision`);
  const reasonCode = validateReason(record.reasonCode, `${label} reasonCode`);
  validateDecisionReason(decision, reasonCode);
  const requiredApproverCapability = validateDecisionSpecificFields(record, decision, label);
  const common = {
    authorityMode,
    subjectId: validateIdentifier(record.subjectId, `${label} subjectId`),
    subjectType: validatePrincipalType(record.subjectType, `${label} subjectType`),
    actingCredentialId: validateIdentifier(
      record.actingCredentialId,
      `${label} actingCredentialId`,
    ),
    effectiveScopeHash: validateContextHash(
      record.effectiveScopeHash,
      `${label} effectiveScopeHash`,
    ),
    action: validateAction(record.action, `${label} action`),
    actionSensitivity: validateActionSensitivity(
      record.actionSensitivity,
      `${label} actionSensitivity`,
    ),
    resourceId: validateIdentifier(record.resourceId, `${label} resourceId`),
    contextHash: validateContextHash(record.contextHash, `${label} contextHash`),
    policyId: validateIdentifier(record.policyId, `${label} policyId`),
    policyVersion: validateContextHash(record.policyVersion, `${label} policyVersion`),
    decision,
    reasonCode,
    ...(requiredApproverCapability === undefined ? {} : { requiredApproverCapability }),
  };
  if (authorityMode === "DIRECT") {
    if (!Object.hasOwn(record, "credentialId")) {
      return Object.freeze({ ...common, authorityMode: "DIRECT" });
    }
    const credentialId = validateIdentifier(record.credentialId, `${label} credentialId`);
    if (credentialId !== common.actingCredentialId) {
      throw new DomainValidationError(`${label} credentialId must equal actingCredentialId`);
    }
    return Object.freeze({ ...common, authorityMode: "DIRECT", credentialId });
  }
  return Object.freeze({
    ...common,
    authorityMode: "DELEGATED",
    grantorId: validateIdentifier(record.grantorId, `${label} grantorId`),
    grantorType: validatePrincipalType(record.grantorType, `${label} grantorType`),
    grantorCredentialId: validateIdentifier(
      record.grantorCredentialId,
      `${label} grantorCredentialId`,
    ),
    delegationId: validateIdentifier(record.delegationId, `${label} delegationId`),
    delegationBindingHash: validateContextHash(
      record.delegationBindingHash,
      `${label} delegationBindingHash`,
    ),
  });
}

function validateInspectionBinding(value: unknown): ReceiptInspectionBinding {
  const record = requireRecord(value, "receipt inspection binding");
  rejectUnknownKeys(record, allBindingFields, "receipt inspection binding");
  if (Object.keys(record).length === 0) {
    throw new DomainValidationError("receipt inspection binding must not be empty");
  }
  if (Object.values(record).some((entry) => entry === undefined)) {
    throw new DomainValidationError("receipt inspection binding fields must be defined");
  }
  const validated: Record<string, unknown> = {};
  if (record.authorityMode !== undefined) {
    validated.authorityMode = validateAuthorityMode(
      record.authorityMode,
      "receipt inspection authorityMode",
    );
  }
  const identifierFields = [
    "subjectId",
    "actingCredentialId",
    "action",
    "resourceId",
    "policyId",
    "credentialId",
    "grantorId",
    "grantorCredentialId",
    "delegationId",
  ] as const;
  for (const field of identifierFields) {
    if (record[field] !== undefined) {
      validated[field] = field === "action"
        ? validateAction(record[field], `receipt inspection ${field}`)
        : validateIdentifier(record[field], `receipt inspection ${field}`);
    }
  }
  const hashFields = [
    "effectiveScopeHash",
    "contextHash",
    "policyVersion",
    "delegationBindingHash",
  ] as const;
  for (const field of hashFields) {
    if (record[field] !== undefined) {
      validated[field] = validateContextHash(record[field], `receipt inspection ${field}`);
    }
  }
  if (record.subjectType !== undefined) {
    validated.subjectType = validatePrincipalType(
      record.subjectType,
      "receipt inspection subjectType",
    );
  }
  if (record.grantorType !== undefined) {
    validated.grantorType = validatePrincipalType(
      record.grantorType,
      "receipt inspection grantorType",
    );
  }
  if (record.actionSensitivity !== undefined) {
    validated.actionSensitivity = validateActionSensitivity(
      record.actionSensitivity,
      "receipt inspection actionSensitivity",
    );
  }
  if (record.decision !== undefined) {
    validated.decision = validateDecision(record.decision, "receipt inspection decision");
  }
  if (record.reasonCode !== undefined) {
    validated.reasonCode = validateReason(record.reasonCode, "receipt inspection reasonCode");
  }
  if (record.requiredApproverCapability !== undefined) {
    validated.requiredApproverCapability = validateCapability(
      record.requiredApproverCapability,
      "receipt inspection requiredApproverCapability",
    );
  }
  if (validated.decision !== undefined && validated.reasonCode !== undefined) {
    validateDecisionReason(
      validated.decision as DecisionOutcome,
      validated.reasonCode as ReasonCode,
    );
  }
  if (
    validated.decision !== undefined &&
    validated.decision !== "STEP_UP" &&
    validated.requiredApproverCapability !== undefined
  ) {
    throw new DomainValidationError(
      "receipt inspection ALLOW/DENY must not include requiredApproverCapability",
    );
  }
  if (
    validated.authorityMode === "DIRECT" &&
    delegatedOnlyFields.some((field) => validated[field] !== undefined)
  ) {
    throw new DomainValidationError("receipt inspection DIRECT must not include delegated fields");
  }
  if (validated.authorityMode === "DELEGATED" && validated.credentialId !== undefined) {
    throw new DomainValidationError("receipt inspection DELEGATED must not include credentialId");
  }
  if (
    validated.credentialId !== undefined &&
    validated.actingCredentialId !== undefined &&
    validated.credentialId !== validated.actingCredentialId
  ) {
    throw new DomainValidationError(
      "receipt inspection credentialId must equal actingCredentialId",
    );
  }
  return Object.freeze(validated) as ReceiptInspectionBinding;
}

function validatePayload(value: unknown): ReceiptPayload {
  const record = requireRecord(value, "receipt payload");
  const authorityMode = validateAuthorityMode(record.authorityMode, "receipt authorityMode");
  const allowedFields = authorityMode === "DIRECT"
    ? ["version", ...commonBindingFields, ...directOnlyFields, ...conditionalBindingFields, ...payloadTimeFields]
    : ["version", ...commonBindingFields, ...delegatedOnlyFields, ...conditionalBindingFields, ...payloadTimeFields];
  rejectUnknownKeys(record, allowedFields, "receipt payload");
  requireOwnFields(record, ["version", ...commonBindingFields, ...payloadTimeFields], "receipt payload");
  if (record.version !== 2) throw new DomainValidationError("receipt payload version must be 2");
  if (authorityMode === "DELEGATED") {
    requireOwnFields(record, delegatedOnlyFields, "receipt payload");
  }
  const binding = validateBindingRecord(
    Object.fromEntries(allBindingFields.filter((field) => Object.hasOwn(record, field)).map((field) => [field, record[field]])),
    "receipt payload binding",
  );
  const decidedAt = validateTimestamp(record.decidedAt, "receipt decidedAt");
  const issuedAt = validateTimestamp(record.issuedAt, "receipt issuedAt");
  const expiresAt = validateTimestamp(record.expiresAt, "receipt expiresAt");
  if (
    timestampMillis(decidedAt) > timestampMillis(issuedAt) ||
    timestampMillis(issuedAt) >= timestampMillis(expiresAt)
  ) {
    throw new DomainValidationError("receipt times are contradictory");
  }
  return Object.freeze({
    version: 2,
    ...binding,
    nonce: validateIdentifier(record.nonce, "receipt nonce"),
    decidedAt,
    issuedAt,
    expiresAt,
  }) as ReceiptPayload;
}

function signatureFor(payload: ReceiptPayload, key: Uint8Array): Buffer {
  return createHmac("sha256", key)
    .update("zkyc-receipt-v2\0", "utf8")
    .update(canonicalJson(payload), "utf8")
    .digest();
}

function withinExpiry(receipt: ReceiptPayload, authorityObject: { readonly expiresAt: string }): boolean {
  return timestampMillis(receipt.expiresAt) <= timestampMillis(authorityObject.expiresAt);
}

function directAuthorityValid(payload: DirectReceiptPayload, acting: Credential): boolean {
  return payload.effectiveScopeHash === acting.scopeHash &&
    acting.allowedActions.includes(payload.action) &&
    acting.allowedResourceIds.includes(payload.resourceId) &&
    withinExpiry(payload, acting);
}

function delegatedAuthorityValid(
  payload: DelegatedReceiptPayload,
  acting: Credential,
  grantor: Credential,
  delegation: CapabilityDelegation,
): boolean {
  return delegation.delegateId === payload.subjectId &&
    delegation.delegateType === payload.subjectType &&
    delegation.grantorId === payload.grantorId &&
    delegation.grantorType === payload.grantorType &&
    delegation.grantorCredentialId === payload.grantorCredentialId &&
    delegation.policyId === payload.policyId &&
    delegation.policyVersion === payload.policyVersion &&
    delegation.scopeHash === payload.effectiveScopeHash &&
    delegation.delegationBindingHash === payload.delegationBindingHash &&
    grantor.id === delegation.grantorCredentialId &&
    grantor.principalId === delegation.grantorId &&
    grantor.principalType === delegation.grantorType &&
    grantor.allowedActions.includes(payload.action) &&
    grantor.allowedResourceIds.includes(payload.resourceId) &&
    delegation.allowedActions.includes(payload.action) &&
    delegation.allowedResourceIds.includes(payload.resourceId) &&
    withinExpiry(payload, acting) &&
    withinExpiry(payload, grantor) &&
    withinExpiry(payload, delegation);
}

function authorityFailureCode(payload: ReceiptPayload): ReceiptVerificationCode {
  return payload.authorityMode === "DIRECT"
    ? "RECEIPT_CREDENTIAL_INVALID"
    : "RECEIPT_AUTHORITY_INVALID";
}

function inspectAuthority(
  payload: ReceiptPayload,
  credentialAuthority: unknown,
  delegationAuthority: unknown,
  at: string,
): ReceiptVerificationCode | undefined {
  if (!(credentialAuthority instanceof CredentialAuthority)) {
    return authorityFailureCode(payload);
  }
  if (credentialAuthority.resolvePolicy(payload.policyId, payload.policyVersion) === undefined) {
    return "RECEIPT_AUTHORITY_INVALID";
  }
  const liveBinding: LiveDecisionAuthorityBinding = {
    authorityMode: payload.authorityMode,
    subjectId: payload.subjectId,
    subjectType: payload.subjectType,
    actingCredentialId: payload.actingCredentialId,
    effectiveScopeHash: payload.effectiveScopeHash,
    action: payload.action,
    actionSensitivity: payload.actionSensitivity,
    resourceId: payload.resourceId,
    policyId: payload.policyId,
    policyVersion: payload.policyVersion,
    outcome: payload.decision,
    reasonCode: payload.reasonCode,
    ...(payload.requiredApproverCapability === undefined
      ? {}
      : { requiredApproverCapability: payload.requiredApproverCapability }),
    ...(payload.authorityMode === "DIRECT"
      ? (payload.credentialId === undefined ? {} : { credentialId: payload.credentialId })
      : {
        grantorId: payload.grantorId,
        grantorType: payload.grantorType,
        grantorCredentialId: payload.grantorCredentialId,
        delegationId: payload.delegationId,
        delegationBindingHash: payload.delegationBindingHash,
      }),
  };
  if (!revalidateLiveDecisionAuthority({
    binding: liveBinding,
    at,
    credentialAuthority,
    ...(delegationAuthority instanceof DelegationAuthority ? { delegationAuthority } : {}),
  })) {
    return authorityFailureCode(payload);
  }
  const acting = credentialAuthority.getActiveCredentialById(
    payload.actingCredentialId,
    at,
    payload.subjectId,
    payload.subjectType,
  );
  if (acting === undefined) return authorityFailureCode(payload);
  if (payload.authorityMode === "DIRECT") {
    return directAuthorityValid(payload, acting) ? undefined : "RECEIPT_CREDENTIAL_INVALID";
  }
  if (
    !(delegationAuthority instanceof DelegationAuthority) ||
    !delegationAuthority.usesCredentialAuthority(credentialAuthority)
  ) {
    return "RECEIPT_AUTHORITY_INVALID";
  }
  const delegation = delegationAuthority.getActiveDelegationById(payload.delegationId, at);
  const grantor = credentialAuthority.getActiveCredentialById(
    payload.grantorCredentialId,
    at,
    payload.grantorId,
    payload.grantorType,
  );
  if (
    delegation === undefined ||
    grantor === undefined ||
    !delegatedAuthorityValid(payload, acting, grantor, delegation)
  ) {
    return "RECEIPT_AUTHORITY_INVALID";
  }
  return undefined;
}

function authorityConfiguration(
  value: CredentialAuthority | ReceiptAuthorityConfiguration,
  delegated?: DelegationAuthority,
): ReceiptAuthorityConfiguration {
  if (value instanceof CredentialAuthority) {
    if (delegated !== undefined && !delegated.usesCredentialAuthority(value)) {
      throw new DomainValidationError(
        "receipt delegation authority must use the configured credential authority",
      );
    }
    return Object.freeze({
      credentialAuthority: value,
      ...(delegated === undefined ? {} : { delegationAuthority: delegated }),
    });
  }
  const record = requireRecord(value, "receipt authority configuration");
  rejectUnknownKeys(
    record,
    ["credentialAuthority", "delegationAuthority"],
    "receipt authority configuration",
  );
  if (!(record.credentialAuthority instanceof CredentialAuthority)) {
    throw new DomainValidationError("receipt authority configuration requires CredentialAuthority");
  }
  if (
    record.delegationAuthority !== undefined &&
    !(record.delegationAuthority instanceof DelegationAuthority)
  ) {
    throw new DomainValidationError("receipt delegation authority is invalid");
  }
  if (
    record.delegationAuthority instanceof DelegationAuthority &&
    !record.delegationAuthority.usesCredentialAuthority(record.credentialAuthority)
  ) {
    throw new DomainValidationError(
      "receipt delegation authority must use the configured credential authority",
    );
  }
  return Object.freeze({
    credentialAuthority: record.credentialAuthority,
    ...(record.delegationAuthority === undefined
      ? {}
      : { delegationAuthority: record.delegationAuthority }),
  });
}

export function signReceipt(
  payloadValue: ReceiptPayload,
  key: Uint8Array,
  credentialAuthority: CredentialAuthority,
  delegationAuthority?: DelegationAuthority,
): SignedReceipt;
export function signReceipt(
  payloadValue: ReceiptPayload,
  key: Uint8Array,
  authorities: ReceiptAuthorityConfiguration,
): SignedReceipt;
export function signReceipt(
  payloadValue: ReceiptPayload,
  key: Uint8Array,
  authorities: CredentialAuthority | ReceiptAuthorityConfiguration,
  delegated?: DelegationAuthority,
): SignedReceipt {
  validateKey(key);
  const payload = validatePayload(payloadValue);
  const configured = authorityConfiguration(authorities, delegated);
  const authorityError = inspectAuthority(
    payload,
    configured.credentialAuthority,
    configured.delegationAuthority,
    payload.issuedAt,
  );
  if (authorityError !== undefined) {
    throw new DomainValidationError(`receipt authority revalidation failed: ${authorityError}`);
  }
  return Object.freeze({
    algorithm: "HMAC-SHA256",
    payload,
    signature: signatureFor(payload, key).toString("base64url"),
  });
}

export function verifyReceipt(
  value: unknown,
  key: Uint8Array,
  options: { at: string; expected?: ReceiptInspectionBinding },
): ReceiptVerification {
  let payload: ReceiptPayload;
  let signature: Buffer;
  let at: string;
  let expected: ReceiptInspectionBinding | undefined;
  try {
    validateKey(key);
    const receipt = requireRecord(value, "receipt");
    rejectUnknownKeys(receipt, ["algorithm", "payload", "signature"], "receipt");
    requireOwnFields(receipt, ["algorithm", "payload", "signature"], "receipt");
    if (receipt.algorithm !== "HMAC-SHA256" || typeof receipt.signature !== "string") {
      return { valid: false, reasonCode: "RECEIPT_MALFORMED" };
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(receipt.signature)) {
      return { valid: false, reasonCode: "RECEIPT_MALFORMED" };
    }
    payload = validatePayload(receipt.payload);
    signature = Buffer.from(receipt.signature, "base64url");
    at = validateTimestamp(options.at, "receipt verification time");
    if (options.expected !== undefined) {
      try {
        expected = validateInspectionBinding(options.expected);
      } catch {
        return { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" };
      }
    }
  } catch {
    return { valid: false, reasonCode: "RECEIPT_MALFORMED" };
  }
  const expectedSignature = signatureFor(payload, key);
  if (signature.length !== expectedSignature.length || !timingSafeEqual(signature, expectedSignature)) {
    return { valid: false, reasonCode: "RECEIPT_SIGNATURE_INVALID" };
  }
  const now = timestampMillis(at);
  if (now < timestampMillis(payload.issuedAt)) {
    return { valid: false, reasonCode: "RECEIPT_NOT_YET_VALID" };
  }
  if (now >= timestampMillis(payload.expiresAt)) {
    return { valid: false, reasonCode: "RECEIPT_EXPIRED" };
  }
  if (expected !== undefined) {
    for (const [field, expectedValue] of Object.entries(expected)) {
      if (payload[field as keyof ReceiptPayload] !== expectedValue) {
        return { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" };
      }
    }
  }
  return { valid: true, reasonCode: "RECEIPT_VALID" };
}

export async function verifyAndConsumeReceipt(
  receipt: unknown,
  key: Uint8Array,
  nonceStore: AtomicNonceStore,
  credentialAuthority: CredentialAuthority,
  options: ReceiptConsumptionOptions,
): Promise<ReceiptVerification> {
  let expected: ReceiptExpectedBinding;
  let at: string;
  try {
    expected = validateBindingRecord(options?.expected, "receipt expected binding");
    at = validateTimestamp(options?.at, "receipt consumption time");
  } catch {
    return { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" };
  }
  const verification = verifyReceipt(receipt, key, { at, expected });
  if (!verification.valid) return verification;
  const payload = (receipt as SignedReceipt).payload;
  if (payload.decision !== "ALLOW" || payload.reasonCode !== "POLICY_ALLOW") {
    return { valid: false, reasonCode: "RECEIPT_NOT_AUTHORIZING" };
  }
  const authorityError = inspectAuthority(
    payload,
    credentialAuthority,
    options.delegationAuthority,
    at,
  );
  if (authorityError !== undefined) {
    return { valid: false, reasonCode: authorityError };
  }
  const nonceKey = `receipt-v2:${sha256Version(payload.nonce).slice("sha256:".length)}`;
  let consumed: boolean;
  try {
    if (typeof nonceStore?.consume !== "function") {
      return { valid: false, reasonCode: "RECEIPT_REPLAYED" };
    }
    consumed = await nonceStore.consume(nonceKey, payload.expiresAt, at);
  } catch {
    return { valid: false, reasonCode: "RECEIPT_REPLAYED" };
  }
  if (!consumed) return { valid: false, reasonCode: "RECEIPT_REPLAYED" };
  return verification;
}
