import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJson, sha256Version } from "./canonical.js";
import { CredentialAuthority } from "./credentials.js";
import {
  DECISION_OUTCOMES,
  REASON_CODES,
  DomainValidationError,
  rejectUnknownKeys,
  requireRecord,
  timestampMillis,
  validateAction,
  validateActionSensitivity,
  validateContextHash,
  validateIdentifier,
  validateTimestamp,
  type ActionSensitivity,
  type DecisionOutcome,
  type ReasonCode,
} from "./domain.js";
import type { AtomicNonceStore } from "./nonce.js";

export interface ReceiptPayload {
  readonly version: 1;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId: string;
  readonly decision: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly nonce: string;
  readonly decidedAt: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

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
  | "RECEIPT_REPLAYED";

export interface ReceiptVerification {
  readonly valid: boolean;
  readonly reasonCode: ReceiptVerificationCode;
}

export interface ReceiptExpectedBinding {
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId: string;
  readonly decision: DecisionOutcome;
  readonly reasonCode: ReasonCode;
}

export type ReceiptInspectionBinding = Partial<ReceiptExpectedBinding>;

const expectedBindingFields = [
  "subjectId",
  "action",
  "actionSensitivity",
  "resourceId",
  "contextHash",
  "policyId",
  "policyVersion",
  "credentialId",
  "decision",
  "reasonCode",
] as const satisfies readonly (keyof ReceiptExpectedBinding)[];

function validateKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength < 32) {
    throw new DomainValidationError("receipt HMAC key must contain at least 32 bytes");
  }
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

function validateExpectedBinding(value: unknown): ReceiptExpectedBinding {
  const record = requireRecord(value, "receipt expected binding");
  rejectUnknownKeys(record, expectedBindingFields, "receipt expected binding");
  if (expectedBindingFields.some((field) => !Object.hasOwn(record, field))) {
    throw new DomainValidationError("receipt expected binding must include every field");
  }
  if (!DECISION_OUTCOMES.includes(record.decision as DecisionOutcome)) {
    throw new DomainValidationError("receipt expected decision is unsupported");
  }
  if (!REASON_CODES.includes(record.reasonCode as ReasonCode)) {
    throw new DomainValidationError("receipt expected reasonCode is unsupported");
  }
  const decision = record.decision as DecisionOutcome;
  const reasonCode = record.reasonCode as ReasonCode;
  validateDecisionReason(decision, reasonCode);
  return Object.freeze({
    subjectId: validateIdentifier(record.subjectId, "receipt expected subjectId"),
    action: validateAction(record.action, "receipt expected action"),
    actionSensitivity: validateActionSensitivity(
      record.actionSensitivity,
      "receipt expected actionSensitivity",
    ),
    resourceId: validateIdentifier(record.resourceId, "receipt expected resourceId"),
    contextHash: validateContextHash(record.contextHash, "receipt expected contextHash"),
    policyId: validateIdentifier(record.policyId, "receipt expected policyId"),
    policyVersion: validateIdentifier(record.policyVersion, "receipt expected policyVersion"),
    credentialId: validateIdentifier(record.credentialId, "receipt expected credentialId"),
    decision,
    reasonCode,
  });
}

function validatePayload(value: unknown): ReceiptPayload {
  const record = requireRecord(value, "receipt payload");
  rejectUnknownKeys(
    record,
    [
      "version",
      "subjectId",
      "action",
      "actionSensitivity",
      "resourceId",
      "contextHash",
      "policyId",
      "policyVersion",
      "credentialId",
      "decision",
      "reasonCode",
      "nonce",
      "decidedAt",
      "issuedAt",
      "expiresAt",
    ],
    "receipt payload",
  );
  if (record.version !== 1) throw new DomainValidationError("receipt payload version must be 1");
  if (!DECISION_OUTCOMES.includes(record.decision as DecisionOutcome)) {
    throw new DomainValidationError("receipt decision is unsupported");
  }
  if (!REASON_CODES.includes(record.reasonCode as ReasonCode)) {
    throw new DomainValidationError("receipt reasonCode is unsupported");
  }
  const decision = record.decision as DecisionOutcome;
  const reasonCode = record.reasonCode as ReasonCode;
  validateDecisionReason(decision, reasonCode);
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
    version: 1,
    subjectId: validateIdentifier(record.subjectId, "receipt subjectId"),
    action: validateAction(record.action, "receipt action"),
    actionSensitivity: validateActionSensitivity(record.actionSensitivity, "receipt actionSensitivity"),
    resourceId: validateIdentifier(record.resourceId, "receipt resourceId"),
    contextHash: validateContextHash(record.contextHash, "receipt contextHash"),
    policyId: validateIdentifier(record.policyId, "receipt policyId"),
    policyVersion: validateIdentifier(record.policyVersion, "receipt policyVersion"),
    credentialId: validateIdentifier(record.credentialId, "receipt credentialId"),
    decision,
    reasonCode,
    nonce: validateIdentifier(record.nonce, "receipt nonce"),
    decidedAt,
    issuedAt,
    expiresAt,
  });
}

function signatureFor(payload: ReceiptPayload, key: Uint8Array): Buffer {
  return createHmac("sha256", key).update(canonicalJson(payload), "utf8").digest();
}

/**
 * Trusted issuer-side primitive. Callers must construct the payload from the
 * corresponding deterministic evaluator output; structural validity alone is
 * not proof of policy-decision provenance.
 */
export function signReceipt(payloadValue: ReceiptPayload, key: Uint8Array): SignedReceipt {
  validateKey(key);
  const payload = validatePayload(payloadValue);
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
      const expectedRecord = requireRecord(options.expected, "receipt inspection binding");
      rejectUnknownKeys(expectedRecord, expectedBindingFields, "receipt inspection binding");
      if (Object.keys(expectedRecord).length === 0) {
        return { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" };
      }
      expected = expectedRecord as ReceiptInspectionBinding;
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
      if (expectedValue !== undefined && payload[field as keyof ReceiptPayload] !== expectedValue) {
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
  options: { at: string; expected: ReceiptExpectedBinding },
): Promise<ReceiptVerification> {
  let expected: ReceiptExpectedBinding;
  try {
    expected = validateExpectedBinding(options?.expected);
  } catch {
    return { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" };
  }
  const verification = verifyReceipt(receipt, key, { at: options.at, expected });
  if (!verification.valid) return verification;
  const payload = (receipt as SignedReceipt).payload;
  if (payload.decision !== "ALLOW" || payload.reasonCode !== "POLICY_ALLOW") {
    return { valid: false, reasonCode: "RECEIPT_NOT_AUTHORIZING" };
  }
  if (!(credentialAuthority instanceof CredentialAuthority)) {
    return { valid: false, reasonCode: "RECEIPT_CREDENTIAL_INVALID" };
  }
  const credentialStatus = credentialAuthority.checkCredentialById(
    payload.credentialId,
    options.at,
    payload.subjectId,
  );
  if (!credentialStatus.valid) {
    return { valid: false, reasonCode: "RECEIPT_CREDENTIAL_INVALID" };
  }
  const nonceKey = `receipt:${sha256Version(payload.nonce).slice("sha256:".length)}`;
  const consumed = await nonceStore.consume(nonceKey, payload.expiresAt, options.at);
  if (!consumed) return { valid: false, reasonCode: "RECEIPT_REPLAYED" };
  return verification;
}
