import { canonicalJson, sha256Version } from "./canonical.js";
import { CredentialAuthority, type Credential } from "./credentials.js";
import {
  DomainValidationError,
  createPrincipal,
  timestampMillis,
  validateAction,
  validateActionSensitivity,
  validateCapability,
  validateContextHash,
  validateIdentifier,
  validateTimestamp,
  type ActionSensitivity,
  type Principal,
} from "./domain.js";
import type { AccessDecision } from "./evaluation.js";
import type { AtomicNonceStore } from "./nonce.js";

export type StepUpStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

export interface StepUpRequest {
  readonly id: string;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId: string;
  readonly requiredApproverCapability: string;
  readonly requestedAt: string;
  readonly expiresAt: string;
  readonly status: StepUpStatus;
}

export interface StepUpAuthorization {
  readonly version: 1;
  readonly id: string;
  readonly requestId: string;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId: string;
  readonly approvedBy: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export type StepUpFailureCode =
  | "STEP_UP_NOT_FOUND"
  | "STEP_UP_EXPIRED"
  | "STEP_UP_ALREADY_RESOLVED"
  | "STEP_UP_REJECTED"
  | "APPROVER_CREDENTIAL_INVALID"
  | "APPROVER_CAPABILITY_MISSING"
  | "INVALID_INPUT";

export type StepUpResolutionResult =
  | { readonly ok: true; readonly authorization: StepUpAuthorization }
  | { readonly ok: false; readonly reasonCode: StepUpFailureCode };

interface RequestRecord {
  request: StepUpRequest;
  authorization?: StepUpAuthorization;
}

export class HumanStepUpService {
  readonly #credentialAuthority: CredentialAuthority;
  readonly #nonceStore: AtomicNonceStore;
  readonly #requests = new Map<string, RequestRecord>();
  readonly #authorizations = new Map<string, StepUpAuthorization>();

  constructor(input: { credentialAuthority: CredentialAuthority; nonceStore: AtomicNonceStore }) {
    if (!(input.credentialAuthority instanceof CredentialAuthority)) {
      throw new DomainValidationError("credentialAuthority is required");
    }
    if (typeof input.nonceStore?.consume !== "function") {
      throw new DomainValidationError("an AtomicNonceStore is required");
    }
    this.#credentialAuthority = input.credentialAuthority;
    this.#nonceStore = input.nonceStore;
  }

  /**
   * Trusted issuer-side primitive. The caller must pass the corresponding
   * deterministic evaluator output; a plain object is not provenance proof.
   */
  createRequest(input: { id: string; decision: AccessDecision; expiresAt: string }): StepUpRequest {
    const id = validateIdentifier(input.id, "step-up request id");
    if (this.#requests.has(id)) throw new DomainValidationError(`step-up request already exists: ${id}`);
    const decision = input.decision;
    if (
      decision.outcome !== "STEP_UP" ||
      decision.reasonCode !== "HUMAN_APPROVAL_REQUIRED" ||
      decision.credentialId === undefined ||
      decision.requiredApproverCapability === undefined
    ) {
      throw new DomainValidationError("step-up requests require a bound STEP_UP decision");
    }
    const requestedAt = validateTimestamp(decision.decidedAt, "step-up requestedAt");
    const expiresAt = validateTimestamp(input.expiresAt, "step-up expiresAt");
    if (timestampMillis(expiresAt) <= timestampMillis(requestedAt)) {
      throw new DomainValidationError("step-up expiry must be after request time");
    }
    const request = Object.freeze({
      id,
      subjectId: validateIdentifier(decision.subjectId, "step-up subjectId"),
      action: validateAction(decision.action, "step-up action"),
      actionSensitivity: validateActionSensitivity(
        decision.actionSensitivity,
        "step-up actionSensitivity",
      ),
      resourceId: validateIdentifier(decision.resourceId, "step-up resourceId"),
      contextHash: validateContextHash(decision.contextHash, "step-up contextHash"),
      policyId: validateIdentifier(decision.policyId, "step-up policyId"),
      policyVersion: validateIdentifier(decision.policyVersion, "step-up policyVersion"),
      credentialId: validateIdentifier(decision.credentialId, "step-up credentialId"),
      requiredApproverCapability: validateCapability(
        decision.requiredApproverCapability,
        "step-up requiredApproverCapability",
      ),
      requestedAt,
      expiresAt,
      status: "PENDING" as const,
    });
    const subjectCredentialStatus = this.#credentialAuthority.checkCredentialById(
      request.credentialId,
      requestedAt,
      request.subjectId,
    );
    if (!subjectCredentialStatus.valid) {
      throw new DomainValidationError("step-up decision credential is not currently valid");
    }
    this.#requests.set(id, { request });
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
    let at: string;
    let approver: Principal;
    try {
      requestId = validateIdentifier(input.requestId, "requestId");
      at = validateTimestamp(input.at, "resolution time");
      approver = createPrincipal(input.approver);
      if (input.resolution !== "APPROVE" && input.resolution !== "REJECT") {
        return { ok: false, reasonCode: "INVALID_INPUT" };
      }
    } catch {
      return { ok: false, reasonCode: "INVALID_INPUT" };
    }
    const record = this.#requests.get(requestId);
    if (record === undefined) return { ok: false, reasonCode: "STEP_UP_NOT_FOUND" };
    const request = record.request;
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
    if (typeof input.approverCredential !== "object" || input.approverCredential === null) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    if (
      input.approverCredential.principalId !== approver.id ||
      canonicalJson(input.approverCredential.affiliations) !== canonicalJson(approver.affiliations)
    ) {
      return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    }
    const status = this.#credentialAuthority.checkCredential(input.approverCredential, at);
    if (!status.valid) return { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" };
    if (!input.approverCredential.capabilities.includes(request.requiredApproverCapability)) {
      return { ok: false, reasonCode: "APPROVER_CAPABILITY_MISSING" };
    }
    if (input.resolution === "REJECT") {
      record.request = Object.freeze({ ...request, status: "REJECTED" });
      return { ok: false, reasonCode: "STEP_UP_REJECTED" };
    }

    const authorizationBody = {
      requestId: request.id,
      subjectId: request.subjectId,
      action: request.action,
      actionSensitivity: request.actionSensitivity,
      resourceId: request.resourceId,
      contextHash: request.contextHash,
      policyId: request.policyId,
      policyVersion: request.policyVersion,
      credentialId: request.credentialId,
      approvedBy: approver.id,
      issuedAt: at,
      expiresAt: request.expiresAt,
    };
    const authorization = Object.freeze({
      version: 1 as const,
      id: `authorization:${sha256Version(authorizationBody).slice("sha256:".length)}`,
      ...authorizationBody,
    });
    record.request = Object.freeze({ ...request, status: "APPROVED" });
    record.authorization = authorization;
    this.#authorizations.set(authorization.id, authorization);
    return { ok: true, authorization };
  }

  async consumeAuthorization(input: {
    authorization: StepUpAuthorization;
    subjectId: string;
    action: string;
    actionSensitivity: ActionSensitivity;
    resourceId: string;
    contextHash: string;
    policyId: string;
    policyVersion: string;
    credentialId: string;
    at: string;
  }): Promise<boolean> {
    try {
      const at = validateTimestamp(input.at, "authorization consumption time");
      const registered = this.#authorizations.get(input.authorization.id);
      if (registered === undefined || canonicalJson(registered) !== canonicalJson(input.authorization)) return false;
      if (
        input.subjectId !== registered.subjectId ||
        input.action !== registered.action ||
        input.actionSensitivity !== registered.actionSensitivity ||
        input.resourceId !== registered.resourceId ||
        input.contextHash !== registered.contextHash ||
        input.policyId !== registered.policyId ||
        input.policyVersion !== registered.policyVersion ||
        input.credentialId !== registered.credentialId ||
        timestampMillis(at) < timestampMillis(registered.issuedAt) ||
        timestampMillis(at) >= timestampMillis(registered.expiresAt)
      ) {
        return false;
      }
      const credentialStatus = this.#credentialAuthority.checkCredentialById(
        registered.credentialId,
        at,
        registered.subjectId,
      );
      if (!credentialStatus.valid) return false;
      return this.#nonceStore.consume(
        `step-up:${registered.id}`,
        registered.expiresAt,
        at,
      );
    } catch {
      return false;
    }
  }
}
