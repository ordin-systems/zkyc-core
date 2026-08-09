import type {
  AccessDecision,
  Affiliation,
  Credential,
  DecisionLogEntry,
  ReceiptPayload,
  SignedReceipt,
  StepUpAuthorization,
  StepUpRequest,
} from "./index.js";

export class InvalidProtocolResponse extends Error {
  constructor() {
    super("response does not match the zKYC reference protocol");
    this.name = "InvalidProtocolResponse";
  }
}

type JsonRecord = Record<string, unknown>;

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

function stringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value)) invalid();
  return value.map(identifier);
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
  return value.map(affiliation);
}

function sensitivity(value: unknown): "ROUTINE" | "SENSITIVE" | "CRITICAL" {
  if (value !== "ROUTINE" && value !== "SENSITIVE" && value !== "CRITICAL") invalid();
  return value;
}

function outcome(value: unknown): "ALLOW" | "DENY" | "STEP_UP" {
  if (value !== "ALLOW" && value !== "DENY" && value !== "STEP_UP") invalid();
  return value;
}

function reasonCode(value: unknown): string {
  const output = stringField(value);
  if (!/^[A-Z][A-Z0-9_]*$/.test(output)) invalid();
  return output;
}

function validateCredentialValue(value: unknown): Credential {
  const item = record(
    value,
    ["version", "id", "issuerId", "principalId", "affiliations", "capabilities", "issuedAt", "expiresAt", "unverifiedMetadata"],
    ["version", "id", "issuerId", "principalId", "affiliations", "capabilities", "issuedAt", "expiresAt"],
  );
  if (item.version !== 1) invalid();
  identifier(item.id);
  identifier(item.issuerId);
  identifier(item.principalId);
  affiliations(item.affiliations);
  stringArray(item.capabilities);
  const issuedAt = timestamp(item.issuedAt);
  const expiresAt = timestamp(item.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) invalid();
  if (item.unverifiedMetadata !== undefined) {
    const metadata = record(
      item.unverifiedMetadata,
      ["zkPassProofId", "contextualProofIds"],
      [],
    );
    if (metadata.zkPassProofId !== undefined) identifier(metadata.zkPassProofId);
    if (metadata.contextualProofIds !== undefined) stringArray(metadata.contextualProofIds);
  }
  return item as unknown as Credential;
}

function validateDecisionValue(value: unknown): AccessDecision {
  const item = record(
    value,
    [
      "outcome", "reasonCode", "subjectId", "action", "actionSensitivity", "resourceId",
      "contextHash", "policyId", "policyVersion", "credentialId", "decidedAt", "requiredApproverCapability",
    ],
    [
      "outcome", "reasonCode", "subjectId", "action", "actionSensitivity", "resourceId",
      "contextHash", "policyId", "policyVersion", "decidedAt",
    ],
  );
  const decisionOutcome = outcome(item.outcome);
  const decisionReason = reasonCode(item.reasonCode);
  if (decisionOutcome === "ALLOW" && decisionReason !== "POLICY_ALLOW") invalid();
  if (decisionOutcome === "STEP_UP" && decisionReason !== "HUMAN_APPROVAL_REQUIRED") invalid();
  if (decisionOutcome === "DENY" && (decisionReason === "POLICY_ALLOW" || decisionReason === "HUMAN_APPROVAL_REQUIRED")) invalid();
  identifier(item.subjectId);
  identifier(item.action);
  sensitivity(item.actionSensitivity);
  identifier(item.resourceId);
  hash(item.contextHash);
  identifier(item.policyId);
  hash(item.policyVersion);
  timestamp(item.decidedAt);
  if (item.credentialId !== undefined) identifier(item.credentialId);
  if (item.requiredApproverCapability !== undefined) identifier(item.requiredApproverCapability);
  return item as unknown as AccessDecision;
}

function validateReceiptPayloadValue(value: unknown): ReceiptPayload {
  const item = record(value, [
    "version", "subjectId", "action", "actionSensitivity", "resourceId", "contextHash", "policyId",
    "policyVersion", "credentialId", "decision", "reasonCode", "nonce", "decidedAt", "issuedAt", "expiresAt",
  ]);
  if (item.version !== 1) invalid();
  identifier(item.subjectId);
  identifier(item.action);
  sensitivity(item.actionSensitivity);
  identifier(item.resourceId);
  hash(item.contextHash);
  identifier(item.policyId);
  hash(item.policyVersion);
  identifier(item.credentialId);
  if (outcome(item.decision) !== "ALLOW" || reasonCode(item.reasonCode) !== "POLICY_ALLOW") invalid();
  identifier(item.nonce);
  timestamp(item.decidedAt);
  timestamp(item.issuedAt);
  timestamp(item.expiresAt);
  return item as unknown as ReceiptPayload;
}

function validateReceiptValue(value: unknown): SignedReceipt {
  const item = record(value, ["algorithm", "payload", "signature"]);
  if (item.algorithm !== "HMAC-SHA256") invalid();
  validateReceiptPayloadValue(item.payload);
  const signature = stringField(item.signature);
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) invalid();
  return item as unknown as SignedReceipt;
}

function validateStepUpRequestValue(value: unknown): StepUpRequest {
  const item = record(value, [
    "id", "subjectId", "action", "actionSensitivity", "resourceId", "contextHash", "policyId",
    "policyVersion", "credentialId", "requiredApproverCapability", "requestedAt", "expiresAt", "status",
  ]);
  identifier(item.id);
  identifier(item.subjectId);
  identifier(item.action);
  sensitivity(item.actionSensitivity);
  identifier(item.resourceId);
  hash(item.contextHash);
  identifier(item.policyId);
  hash(item.policyVersion);
  identifier(item.credentialId);
  identifier(item.requiredApproverCapability);
  timestamp(item.requestedAt);
  timestamp(item.expiresAt);
  if (!["PENDING", "APPROVED", "REJECTED", "EXPIRED"].includes(String(item.status))) invalid();
  return item as unknown as StepUpRequest;
}

function validateAuthorizationValue(value: unknown): StepUpAuthorization {
  const item = record(value, [
    "version", "id", "requestId", "subjectId", "action", "actionSensitivity", "resourceId", "contextHash",
    "policyId", "policyVersion", "credentialId", "approvedBy", "issuedAt", "expiresAt",
  ]);
  if (item.version !== 1) invalid();
  identifier(item.id);
  identifier(item.requestId);
  identifier(item.subjectId);
  identifier(item.action);
  sensitivity(item.actionSensitivity);
  identifier(item.resourceId);
  hash(item.contextHash);
  identifier(item.policyId);
  hash(item.policyVersion);
  identifier(item.credentialId);
  identifier(item.approvedBy);
  timestamp(item.issuedAt);
  timestamp(item.expiresAt);
  return item as unknown as StepUpAuthorization;
}

function assertReceiptMatchesDecision(receipt: SignedReceipt, decision: AccessDecision): void {
  if (
    receipt.payload.subjectId !== decision.subjectId ||
    receipt.payload.action !== decision.action ||
    receipt.payload.actionSensitivity !== decision.actionSensitivity ||
    receipt.payload.resourceId !== decision.resourceId ||
    receipt.payload.contextHash !== decision.contextHash ||
    receipt.payload.policyId !== decision.policyId ||
    receipt.payload.policyVersion !== decision.policyVersion ||
    receipt.payload.credentialId !== decision.credentialId ||
    receipt.payload.decision !== decision.outcome ||
    receipt.payload.reasonCode !== decision.reasonCode
  ) invalid();
}

export function validateHealthResponse(value: unknown) {
  const item = record(value, ["ok", "service", "version", "state"]);
  if (item.ok !== true || item.service !== "zkyc-core-api-reference" || item.version !== "0.2.0" || item.state !== "in-memory-reference-only") invalid();
  return item as { readonly ok: true; readonly service: "zkyc-core-api-reference"; readonly version: "0.2.0"; readonly state: "in-memory-reference-only" };
}

export function validateCredentialResponse(value: unknown): { readonly credential: Credential } {
  const item = record(value, ["credential"]);
  return { credential: validateCredentialValue(item.credential) };
}

export function validateRevocationResponse(value: unknown): { readonly revoked: boolean } {
  const item = record(value, ["revoked"]);
  return { revoked: booleanField(item.revoked) };
}

export function validateEvaluationResponse(value: unknown): { readonly logId: string; readonly decision: AccessDecision; readonly receipt?: SignedReceipt } {
  const item = record(value, ["logId", "decision", "receipt"], ["logId", "decision"]);
  const logId = identifier(item.logId);
  const decision = validateDecisionValue(item.decision);
  if (item.receipt === undefined) return { logId, decision };
  const receipt = validateReceiptValue(item.receipt);
  assertReceiptMatchesDecision(receipt, decision);
  return { logId, decision, receipt };
}

export function validateStepUpRequestResponse(value: unknown): { readonly request: StepUpRequest } {
  const item = record(value, ["request"]);
  return { request: validateStepUpRequestValue(item.request) };
}

export function validateResolutionResponse(value: unknown):
  | { readonly ok: true; readonly authorization: StepUpAuthorization }
  | { readonly ok: false; readonly reasonCode: string } {
  const item = record(value, ["ok", "authorization", "reasonCode"], ["ok"]);
  if (item.ok === true) {
    if (item.authorization === undefined || item.reasonCode !== undefined) invalid();
    return { ok: true, authorization: validateAuthorizationValue(item.authorization) };
  }
  if (item.ok === false) {
    if (item.authorization !== undefined || item.reasonCode === undefined) invalid();
    return { ok: false, reasonCode: reasonCode(item.reasonCode) };
  }
  return invalid();
}

export function validateAuthorizationConsumeResponse(value: unknown): { readonly authorized: boolean } {
  const item = record(value, ["authorized"]);
  return { authorized: booleanField(item.authorized) };
}

export function validateReceiptConsumeResponse(value: unknown): { readonly valid: boolean; readonly reasonCode: string } {
  const item = record(value, ["valid", "reasonCode"]);
  return { valid: booleanField(item.valid), reasonCode: reasonCode(item.reasonCode) };
}

function validateLogEntry(value: unknown): DecisionLogEntry {
  const item = record(value, ["id", "recordedAt", "decision", "receipt"], ["id", "recordedAt", "decision"]);
  identifier(item.id);
  timestamp(item.recordedAt);
  const decision = validateDecisionValue(item.decision);
  if (item.receipt !== undefined) {
    const summary = record(item.receipt, ["algorithm", "payload", "signatureHash"]);
    if (summary.algorithm !== "HMAC-SHA256") invalid();
    const payload = validateReceiptPayloadValue(summary.payload);
    hash(summary.signatureHash);
    assertReceiptMatchesDecision({ algorithm: "HMAC-SHA256", payload, signature: "0".repeat(64) }, decision);
  }
  return item as unknown as DecisionLogEntry;
}

export function validateDecisionLogResponse(value: unknown): { readonly referenceOnly: true; readonly entries: readonly DecisionLogEntry[] } {
  const item = record(value, ["referenceOnly", "entries"]);
  if (item.referenceOnly !== true || !Array.isArray(item.entries)) invalid();
  return { referenceOnly: true, entries: item.entries.map(validateLogEntry) };
}
