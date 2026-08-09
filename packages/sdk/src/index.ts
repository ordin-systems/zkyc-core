import {
  InvalidProtocolResponse,
  validateAuthorizationConsumeResponse,
  validateCredentialResponse,
  validateDecisionLogResponse,
  validateEvaluationResponse,
  validateHealthResponse,
  validateReceiptConsumeResponse,
  validateResolutionResponse,
  validateRevocationResponse,
  validateStepUpRequestResponse,
} from "./validation.js";

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>;

export type ActionSensitivity = "ROUTINE" | "SENSITIVE" | "CRITICAL";
export type DecisionOutcome = "ALLOW" | "DENY" | "STEP_UP";

export interface Affiliation {
  readonly organizationId: string;
  readonly role: string;
}

export interface Principal {
  readonly id: string;
  readonly affiliations: readonly Affiliation[];
}

export interface Credential {
  readonly version: 1;
  readonly id: string;
  readonly issuerId: string;
  readonly principalId: string;
  readonly affiliations: readonly Affiliation[];
  readonly capabilities: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly unverifiedMetadata?: Readonly<Record<string, unknown>>;
}

export interface PolicyRule {
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly requiredCapabilities: readonly string[];
  readonly requiredAffiliations: readonly Affiliation[];
  readonly effect: DecisionOutcome;
  readonly approverCapability?: string;
}

export interface PolicyInput {
  readonly id: string;
  readonly rules: readonly PolicyRule[];
}

export interface AccessDecision {
  readonly outcome: DecisionOutcome;
  readonly reasonCode: string;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId?: string;
  readonly decidedAt: string;
  readonly requiredApproverCapability?: string;
}

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
  readonly reasonCode: string;
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
  readonly reasonCode: string;
}

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
  readonly status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
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

export interface DecisionLogEntry {
  readonly id: string;
  readonly recordedAt: string;
  readonly decision: AccessDecision;
  readonly receipt?: {
    readonly algorithm: "HMAC-SHA256";
    readonly payload: ReceiptPayload;
    readonly signatureHash: string;
  };
}

export interface IssueCredentialRequest {
  readonly principal: Principal;
  readonly capabilities: readonly string[];
  readonly expiresAt: string;
  readonly unverifiedMetadata?: Readonly<Record<string, unknown>>;
}

export interface EvaluateRequest {
  readonly principal: Principal;
  readonly credential: Credential | null;
  readonly action: string;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: PolicyInput;
  readonly issueReceipt: boolean;
  readonly receiptExpiresAt?: string;
}

export interface ResolveStepUpRequest {
  readonly resolution: "APPROVE" | "REJECT";
  readonly approver: Principal;
  readonly approverCredential: Credential;
}

export interface ConsumeStepUpAuthorizationRequest {
  readonly authorization: StepUpAuthorization;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId: string;
}

export class ZkycApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(`zKYC reference API rejected the request (${code})`);
    this.name = "ZkycApiError";
    this.status = status;
    this.code = code;
  }
}

export class ZkycTransportError extends Error {
  readonly code: "NETWORK_ERROR" | "INVALID_RESPONSE";

  constructor(code: "NETWORK_ERROR" | "INVALID_RESPONSE") {
    super(`zKYC reference transport failed (${code})`);
    this.name = "ZkycTransportError";
    this.code = code;
  }
}

export interface ZkycReferenceClientOptions {
  readonly baseUrl: string;
  readonly fetch?: FetchLike;
}

export class ZkycReferenceClient {
  readonly #baseUrl: URL;
  readonly #fetch: FetchLike;

  constructor(options: ZkycReferenceClientOptions) {
    const normalized = options.baseUrl.endsWith("/") ? options.baseUrl : `${options.baseUrl}/`;
    const runtimeLocation = Reflect.get(globalThis, "location") as { readonly href: string } | undefined;
    this.#baseUrl = new URL(normalized, runtimeLocation?.href);
    const fetchImplementation = options.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new ZkycTransportError("NETWORK_ERROR");
    }
    this.#fetch = fetchImplementation.bind(globalThis);
  }

  async #request<T>(
    path: string,
    validate: (value: unknown) => T,
    method = "GET",
    body?: unknown,
  ): Promise<T> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#baseUrl), {
        method,
        ...(body === undefined
          ? {}
          : { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
      });
    } catch {
      throw new ZkycTransportError("NETWORK_ERROR");
    }

    const contentType = response.headers.get("content-type") ?? "";
    const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
    if (mediaType !== "application/json" && !/^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(mediaType)) {
      throw new ZkycTransportError("INVALID_RESPONSE");
    }
    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      throw new ZkycTransportError("INVALID_RESPONSE");
    }
    if (!response.ok) {
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      const record = parsed as Record<string, unknown>;
      if (Object.keys(record).length !== 1 || !Object.hasOwn(record, "error") ||
        typeof record.error !== "object" || record.error === null || Array.isArray(record.error)) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      const errorRecord = record.error as Record<string, unknown>;
      if (Object.keys(errorRecord).some((key) => key !== "code" && key !== "message") ||
        !Object.hasOwn(errorRecord, "code") || !Object.hasOwn(errorRecord, "message") ||
        typeof errorRecord.code !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(errorRecord.code) ||
        typeof errorRecord.message !== "string") {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      const code = errorRecord.code;
      throw new ZkycApiError(response.status, code);
    }
    try {
      return validate(parsed);
    } catch (error) {
      if (error instanceof InvalidProtocolResponse) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      throw error;
    }
  }

  health() {
    return this.#request("health", validateHealthResponse);
  }

  issueCredential(input: IssueCredentialRequest) {
    return this.#request("credentials", validateCredentialResponse, "POST", input);
  }

  revokeCredential(credentialId: string, input: { readonly reason: string }) {
    return this.#request(
      `credentials/${encodeURIComponent(credentialId)}/revoke`,
      validateRevocationResponse,
      "POST",
      input,
    );
  }

  evaluate(input: EvaluateRequest) {
    return this.#request("evaluations", validateEvaluationResponse, "POST", input);
  }

  createStepUpRequest(input: { readonly decisionLogId: string; readonly expiresAt: string }) {
    return this.#request("step-up/requests", validateStepUpRequestResponse, "POST", input);
  }

  resolveStepUpRequest(requestId: string, input: ResolveStepUpRequest) {
    return this.#request(
      `step-up/requests/${encodeURIComponent(requestId)}/resolve`,
      validateResolutionResponse,
      "POST",
      input,
    );
  }

  consumeStepUpAuthorization(input: ConsumeStepUpAuthorizationRequest) {
    return this.#request("step-up/authorizations/consume", validateAuthorizationConsumeResponse, "POST", input);
  }

  consumeReceipt(input: { readonly receipt: SignedReceipt; readonly expected: ReceiptExpectedBinding }) {
    return this.#request(
      "receipts/consume",
      validateReceiptConsumeResponse,
      "POST",
      input,
    );
  }

  getDecisionLog() {
    return this.#request("decision-log", validateDecisionLogResponse);
  }
}
