import { Hono, type Context } from "hono";
import {
  CredentialAuthority,
  DelegationAuthority,
  DelegationValidationError,
  DomainValidationError,
  HumanStepUpService,
  InMemoryAtomicNonceStore,
  PolicyRegistry,
  createPolicy,
  createPrincipal,
  evaluateAccess,
  sha256Version,
  signReceipt,
  verifyAndConsumeReceipt,
  type AccessDecision,
  type AuthorityMode,
  type CapabilityDelegation,
  type Credential,
  type CreatePolicyInput,
  type Policy,
  type Principal,
  type ReceiptExpectedBinding,
  type ReceiptPayload,
  type SignedReceipt,
  type StepUpAuthorization,
  type StepUpAuthorizationBinding,
  type StepUpAuthorizationUsability,
  type StepUpStatus,
} from "@ordin/zkyc-core-reference";

export type ReferenceIdKind =
  | "credential"
  | "delegation"
  | "decision-log"
  | "step-up-request"
  | "receipt-nonce";

export interface ReferenceAppOptions {
  readonly clock: () => string;
  readonly idFactory: (kind: ReferenceIdKind) => string;
  readonly receiptHmacKey: Uint8Array;
  readonly trustedPolicies: readonly CreatePolicyInput[];
  readonly issuerId?: string;
}

export interface DecisionLogEntry {
  readonly id: string;
  readonly recordedAt: string;
  readonly principal: Principal;
  readonly decision: AccessDecision;
  readonly receipt?: {
    readonly algorithm: "HMAC-SHA256";
    readonly payload: ReceiptPayload;
    readonly signatureHash: string;
  };
}

type VerificationStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "INVALID";
type EligibleActionStatus = "ELIGIBLE" | "APPROVAL_REQUIRED" | "INELIGIBLE";
type RequiredApprovalStatus = "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
type RetainedReceiptStatus = "UNCONSUMED" | "CONSUMED" | "REJECTED";

interface RetainedDecisionLogEntry extends DecisionLogEntry {
  readonly policy: Policy;
  readonly actingCredential?: Credential;
  readonly grantorCredential?: Credential;
  readonly delegation?: CapabilityDelegation;
}

interface AuthoritySnapshot {
  readonly verificationStatus: VerificationStatus;
  readonly reasonCode: string;
  readonly delegatedScopeStatus?: VerificationStatus;
}

const receiptCommonBindingFields = [
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

const delegatedBindingFields = [
  "grantorId",
  "grantorType",
  "grantorCredentialId",
  "delegationId",
  "delegationBindingHash",
] as const;

const stepUpCommonBindingFields = [
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
] as const;

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DomainValidationError(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new DomainValidationError(`${label} must be a plain object`);
  }
  const record = Object.fromEntries(Object.entries(value));
  for (const dangerous of ["__proto__", "prototype", "constructor"]) {
    if (Object.hasOwn(record, dangerous)) {
      throw new DomainValidationError(`${label} contains a forbidden field`);
    }
  }
  return record;
}

function exactKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[] = [],
): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(record).some((key) => !allowedSet.has(key))) {
    throw new DomainValidationError("request contains unsupported fields");
  }
  if (required.some((key) => !Object.hasOwn(record, key))) {
    throw new DomainValidationError("request is missing required fields");
  }
}

class ReferenceHttpError extends Error {
  constructor(
    readonly status: 415,
    readonly code: "UNSUPPORTED_MEDIA_TYPE",
  ) {
    super("request media type is unsupported");
    this.name = "ReferenceHttpError";
  }
}

function isJsonMediaType(contentType: string): boolean {
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" ||
    /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(mediaType);
}

async function jsonBody(
  context: Context,
  allowed: readonly string[],
  required: readonly string[] = [],
): Promise<Record<string, unknown>> {
  const contentType = context.req.header("content-type") ?? "";
  if (!isJsonMediaType(contentType)) {
    throw new ReferenceHttpError(415, "UNSUPPORTED_MEDIA_TYPE");
  }
  let value: unknown;
  try {
    value = await context.req.json();
  } catch {
    throw new DomainValidationError("request body is invalid JSON");
  }
  const record = requireRecord(value, "request body");
  exactKeys(record, allowed, required);
  return record;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  return Object.freeze(value);
}

function frozenClone<T>(value: T): T {
  return deepFreeze(cloneJson(value));
}

function invalidRequest(context: Context) {
  return context.json({ error: { code: "INVALID_REQUEST", message: "request body is invalid" } }, 400);
}

function knownCredential(
  authority: CredentialAuthority,
  value: unknown,
  at: string,
): Credential | undefined {
  const status = authority.checkCredential(value, at);
  if (status.code === "CREDENTIAL_MALFORMED" || status.code === "CREDENTIAL_UNKNOWN") {
    return undefined;
  }
  return frozenClone(value as Credential);
}

function knownDelegation(
  authority: DelegationAuthority,
  value: unknown,
  at: string,
): CapabilityDelegation | undefined {
  const status = authority.checkDelegation(value, at);
  if (status.code === "DELEGATION_MALFORMED" || status.code === "DELEGATION_UNKNOWN") {
    return undefined;
  }
  return frozenClone(value as CapabilityDelegation);
}

function trustedPrincipal(fallback: Principal, credential?: Credential): Principal {
  if (credential === undefined) return fallback;
  return createPrincipal({
    id: credential.principalId,
    type: credential.principalType,
    affiliations: credential.affiliations,
  });
}

function receiptBindingFromDecision(decision: AccessDecision): ReceiptExpectedBinding {
  if (
    decision.authorityMode === undefined ||
    decision.subjectType === undefined ||
    decision.actingCredentialId === undefined ||
    decision.effectiveScopeHash === undefined
  ) {
    throw new DomainValidationError("ALLOW decision is missing receipt authority bindings");
  }
  const common = {
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
    decision: decision.outcome,
    reasonCode: decision.reasonCode,
  };
  if (decision.authorityMode === "DIRECT") {
    if (decision.credentialId === undefined) {
      throw new DomainValidationError("direct ALLOW decision is missing credential binding");
    }
    return Object.freeze({
      ...common,
      authorityMode: "DIRECT",
      credentialId: decision.credentialId,
    });
  }
  if (
    decision.grantorId === undefined ||
    decision.grantorType === undefined ||
    decision.grantorCredentialId === undefined ||
    decision.delegationId === undefined ||
    decision.delegationBindingHash === undefined
  ) {
    throw new DomainValidationError("delegated ALLOW decision is missing delegation bindings");
  }
  return Object.freeze({
    ...common,
    authorityMode: "DELEGATED",
    grantorId: decision.grantorId,
    grantorType: decision.grantorType,
    grantorCredentialId: decision.grantorCredentialId,
    delegationId: decision.delegationId,
    delegationBindingHash: decision.delegationBindingHash,
  });
}

function receiptPayloadFromDecision(
  decision: AccessDecision,
  nonce: string,
  issuedAt: string,
  expiresAt: string,
): ReceiptPayload {
  return Object.freeze({
    version: 2,
    ...receiptBindingFromDecision(decision),
    nonce,
    decidedAt: decision.decidedAt,
    issuedAt,
    expiresAt,
  }) as ReceiptPayload;
}

function publicDecisionLogEntry(entry: RetainedDecisionLogEntry): DecisionLogEntry {
  return {
    id: entry.id,
    recordedAt: entry.recordedAt,
    principal: entry.principal,
    decision: entry.decision,
    ...(entry.receipt === undefined ? {} : { receipt: entry.receipt }),
  };
}

function mappedStatus(code: string): VerificationStatus {
  if (code === "ACTIVE") return "ACTIVE";
  if (code.includes("REVOKED")) return "REVOKED";
  if (code.includes("EXPIRED")) return "EXPIRED";
  return "INVALID";
}

function authoritySnapshot(
  entry: RetainedDecisionLogEntry,
  credentialAuthority: CredentialAuthority,
  delegationAuthority: DelegationAuthority,
  at: string,
): AuthoritySnapshot {
  if (entry.actingCredential === undefined) {
    return { verificationStatus: "INVALID", reasonCode: entry.decision.reasonCode };
  }
  const acting = credentialAuthority.checkCredential(entry.actingCredential, at);
  if (entry.decision.authorityMode === "DIRECT") {
    return {
      verificationStatus: mappedStatus(acting.code),
      reasonCode: acting.valid ? entry.decision.reasonCode : acting.code,
    };
  }
  if (entry.grantorCredential === undefined || entry.delegation === undefined) {
    return {
      verificationStatus: "INVALID",
      reasonCode: entry.decision.reasonCode,
      delegatedScopeStatus: "INVALID",
    };
  }
  const grantor = credentialAuthority.checkCredential(entry.grantorCredential, at);
  const delegation = delegationAuthority.checkDelegation(entry.delegation, at, entry.policy);
  const statuses = [acting, grantor, delegation];
  const invalid = statuses.find((status) => !status.valid);
  let verificationStatus: VerificationStatus = "ACTIVE";
  let reasonCode: string = entry.decision.reasonCode;
  for (const target of ["REVOKED", "EXPIRED", "INVALID"] as const) {
    const matched = statuses.find((status) => !status.valid && mappedStatus(status.code) === target);
    if (matched !== undefined) {
      verificationStatus = target;
      reasonCode = matched.code;
      break;
    }
  }
  const delegatedScopeStatuses = [grantor, delegation];
  let delegatedScopeStatus: VerificationStatus = "ACTIVE";
  for (const target of ["REVOKED", "EXPIRED", "INVALID"] as const) {
    if (
      delegatedScopeStatuses.some((status) =>
        !status.valid && mappedStatus(status.code) === target
      )
    ) {
      delegatedScopeStatus = target;
      break;
    }
  }
  return {
    verificationStatus: invalid === undefined ? "ACTIVE" : verificationStatus,
    reasonCode,
    delegatedScopeStatus,
  };
}

function currentApproval(
  entry: RetainedDecisionLogEntry,
  requestId: string | undefined,
  authorization: StepUpAuthorization | undefined,
  stepUpService: HumanStepUpService,
  at: string,
): { readonly status: RequiredApprovalStatus; readonly requestId?: string } {
  if (entry.decision.outcome !== "STEP_UP") return { status: "NOT_REQUIRED" };
  if (requestId === undefined) return { status: "PENDING" };
  const request = stepUpService.getRequest(requestId);
  if (request === undefined) return { status: "PENDING", requestId };
  let status: StepUpStatus = request.status;
  if (status === "PENDING" && Date.parse(at) >= Date.parse(request.expiresAt)) status = "EXPIRED";
  if (
    status === "APPROVED" &&
    authorization !== undefined &&
    Date.parse(at) >= Date.parse(authorization.expiresAt)
  ) {
    status = "EXPIRED";
  }
  return { status, requestId };
}

function eligibleAction(
  entry: RetainedDecisionLogEntry,
  authority: AuthoritySnapshot,
  approval: { readonly status: RequiredApprovalStatus },
  authorizationUsability: StepUpAuthorizationUsability | undefined,
): {
  readonly action: string;
  readonly resourceId: string;
  readonly status: EligibleActionStatus;
  readonly reasonCode: string;
} {
  const common = { action: entry.decision.action, resourceId: entry.decision.resourceId };
  if (authority.verificationStatus !== "ACTIVE") {
    return { ...common, status: "INELIGIBLE", reasonCode: authority.reasonCode };
  }
  if (entry.decision.outcome === "ALLOW") {
    return { ...common, status: "ELIGIBLE", reasonCode: entry.decision.reasonCode };
  }
  if (entry.decision.outcome === "DENY") {
    return { ...common, status: "INELIGIBLE", reasonCode: entry.decision.reasonCode };
  }
  if (approval.status === "APPROVED") {
    if (authorizationUsability?.usable !== true) {
      return {
        ...common,
        status: "INELIGIBLE",
        reasonCode: authorizationUsability?.reasonCode ?? "STEP_UP_NOT_FOUND",
      };
    }
    return { ...common, status: "ELIGIBLE", reasonCode: "STEP_UP_APPROVED" };
  }
  if (approval.status === "REJECTED") {
    return { ...common, status: "INELIGIBLE", reasonCode: "STEP_UP_REJECTED" };
  }
  if (approval.status === "EXPIRED") {
    return {
      ...common,
      status: "INELIGIBLE",
      reasonCode: authorizationUsability?.usable === false
        ? authorizationUsability.reasonCode
        : "STEP_UP_EXPIRED",
    };
  }
  return { ...common, status: "APPROVAL_REQUIRED", reasonCode: entry.decision.reasonCode };
}

function signatureHashFromReceipt(value: unknown): string | undefined {
  try {
    const receipt = requireRecord(value, "receipt");
    if (typeof receipt.signature !== "string") return undefined;
    return sha256Version(receipt.signature);
  } catch {
    return undefined;
  }
}

export function createReferenceApp(options: ReferenceAppOptions): Hono {
  if (typeof options?.clock !== "function" || typeof options?.idFactory !== "function") {
    throw new DomainValidationError("clock and idFactory are required");
  }
  if (!(options.receiptHmacKey instanceof Uint8Array) || options.receiptHmacKey.byteLength < 32) {
    throw new DomainValidationError("receipt HMAC key must contain at least 32 bytes");
  }

  const receiptHmacKey = new Uint8Array(options.receiptHmacKey);
  const issuerId = options.issuerId ?? "issuer:reference-api";
  if (!Array.isArray(options.trustedPolicies)) {
    throw new DomainValidationError("trustedPolicies must be configured before app startup");
  }
  const policyRegistry = new PolicyRegistry({
    policies: options.trustedPolicies.map((policy) => createPolicy(policy)),
  });
  const credentialAuthority = new CredentialAuthority({ issuerId, policyRegistry });
  const delegationAuthority = new DelegationAuthority({ issuerId, credentialAuthority });
  const nonceStore = new InMemoryAtomicNonceStore();
  const stepUpService = new HumanStepUpService({
    credentialAuthority,
    delegationAuthority,
    nonceStore,
  });
  const decisionLog = new Map<string, RetainedDecisionLogEntry>();
  const requestByDecisionLogId = new Map<string, string>();
  const authorizationByRequestId = new Map<string, StepUpAuthorization>();
  const receiptStatusBySignatureHash = new Map<string, RetainedReceiptStatus>();
  const app = new Hono();

  app.use("*", async (context, next) => {
    await next();
    context.header("cache-control", "no-store");
  });

  app.onError((error, context) => {
    if (error instanceof ReferenceHttpError) {
      return context.json({ error: { code: error.code, message: error.message } }, error.status);
    }
    if (error instanceof DelegationValidationError) {
      return context.json({
        error: { code: error.code, message: "delegation request is invalid" },
      }, 400);
    }
    if (error instanceof DomainValidationError || error instanceof SyntaxError) return invalidRequest(context);
    return context.json({ error: { code: "INTERNAL_ERROR", message: "reference adapter failed closed" } }, 500);
  });

  app.get("/health", (context) => context.json({
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.3.0",
    state: "in-memory-reference-only",
  }));

  app.post("/credentials", async (context) => {
    const body = await jsonBody(
      context,
      [
        "principal",
        "capabilities",
        "allowedActions",
        "allowedResourceIds",
        "expiresAt",
        "unverifiedMetadata",
      ],
      ["principal", "capabilities", "allowedActions", "allowedResourceIds", "expiresAt"],
    );
    const now = options.clock();
    const input = {
      id: options.idFactory("credential"),
      principal: createPrincipal(body.principal),
      capabilities: body.capabilities as readonly string[],
      allowedActions: body.allowedActions as readonly string[],
      allowedResourceIds: body.allowedResourceIds as readonly string[],
      issuedAt: now,
      expiresAt: body.expiresAt as string,
      ...(body.unverifiedMetadata === undefined
        ? {}
        : { unverifiedMetadata: body.unverifiedMetadata as never }),
    };
    const credential = credentialAuthority.issueCredential(input);
    return context.json({ credential }, 201);
  });

  app.post("/credentials/:credentialId/revoke", async (context) => {
    const body = await jsonBody(context, ["reason"], ["reason"]);
    const revoked = credentialAuthority.revokeCredential(context.req.param("credentialId"), {
      revokedAt: options.clock(),
      reason: body.reason as string,
    });
    return context.json({ revoked });
  });

  app.post("/delegations", async (context) => {
    const body = await jsonBody(
      context,
      [
        "grantor",
        "grantorCredential",
        "delegate",
        "policy",
        "capabilities",
        "allowedActions",
        "allowedResourceIds",
        "expiresAt",
      ],
      [
        "grantor",
        "grantorCredential",
        "delegate",
        "policy",
        "capabilities",
        "allowedActions",
        "allowedResourceIds",
        "expiresAt",
      ],
    );
    const delegation = delegationAuthority.issueDelegation({
      id: options.idFactory("delegation"),
      grantor: createPrincipal(body.grantor),
      grantorCredential: body.grantorCredential as Credential,
      delegate: createPrincipal(body.delegate),
      policy: createPolicy(body.policy),
      capabilities: body.capabilities as readonly string[],
      allowedActions: body.allowedActions as readonly string[],
      allowedResourceIds: body.allowedResourceIds as readonly string[],
      issuedAt: options.clock(),
      expiresAt: body.expiresAt as string,
    });
    return context.json({ delegation }, 201);
  });

  app.post("/delegations/:delegationId/revoke", async (context) => {
    const body = await jsonBody(context, ["reason"], ["reason"]);
    const revoked = delegationAuthority.revokeDelegation(context.req.param("delegationId"), {
      revokedAt: options.clock(),
      reason: body.reason as string,
    });
    return context.json({ revoked });
  });

  app.post("/evaluations", async (context) => {
    const commonFields = [
      "authorityMode",
      "principal",
      "action",
      "resourceId",
      "actionContext",
      "policy",
      "issueReceipt",
      "receiptExpiresAt",
    ] as const;
    const directFields = [...commonFields, "credential"] as const;
    const delegatedFields = [
      ...commonFields,
      "delegateIdentityCredential",
      "grantorCredential",
      "delegation",
    ] as const;
    const body = await jsonBody(context, [...directFields, ...delegatedFields]);
    if (body.authorityMode !== "DIRECT" && body.authorityMode !== "DELEGATED") {
      throw new DomainValidationError("authorityMode is required");
    }
    const authorityMode: AuthorityMode = body.authorityMode;
    const requiredCommon = [
      "authorityMode",
      "principal",
      "action",
      "resourceId",
      "actionContext",
      "policy",
      "issueReceipt",
    ] as const;
    exactKeys(
      body,
      authorityMode === "DIRECT" ? directFields : delegatedFields,
      authorityMode === "DIRECT"
        ? [...requiredCommon, "credential"]
        : [...requiredCommon, "delegateIdentityCredential", "grantorCredential", "delegation"],
    );
    if (typeof body.issueReceipt !== "boolean") {
      throw new DomainValidationError("issueReceipt must be boolean");
    }

    const now = options.clock();
    const principal = createPrincipal(body.principal);
    const policy = createPolicy(body.policy);
    const decision = authorityMode === "DIRECT"
      ? evaluateAccess({
        authorityMode: "DIRECT",
        principal,
        credential: body.credential as Credential,
        action: body.action,
        resourceId: body.resourceId,
        actionContext: body.actionContext,
        policy,
        at: now,
        credentialAuthority,
      })
      : evaluateAccess({
        authorityMode: "DELEGATED",
        principal,
        delegateIdentityCredential: body.delegateIdentityCredential as Credential,
        grantorCredential: body.grantorCredential as Credential,
        delegation: body.delegation as CapabilityDelegation,
        action: body.action,
        resourceId: body.resourceId,
        actionContext: body.actionContext,
        policy,
        at: now,
        credentialAuthority,
        delegationAuthority,
      });

    const actingCredential = knownCredential(
      credentialAuthority,
      authorityMode === "DIRECT" ? body.credential : body.delegateIdentityCredential,
      now,
    );
    const grantorCredential = authorityMode === "DELEGATED"
      ? knownCredential(credentialAuthority, body.grantorCredential, now)
      : undefined;
    const delegation = authorityMode === "DELEGATED"
      ? knownDelegation(delegationAuthority, body.delegation, now)
      : undefined;
    const retainedPrincipal = trustedPrincipal(principal, actingCredential);

    let receipt: SignedReceipt | undefined;
    if (body.issueReceipt && decision.outcome === "ALLOW") {
      if (body.receiptExpiresAt === undefined) {
        throw new DomainValidationError("receipt expiry is required for ALLOW receipt issuance");
      }
      receipt = signReceipt(
        receiptPayloadFromDecision(
          decision,
          options.idFactory("receipt-nonce"),
          now,
          body.receiptExpiresAt as string,
        ),
        receiptHmacKey,
        credentialAuthority,
        delegationAuthority,
      );
    }

    const logId = options.idFactory("decision-log");
    const retainedReceipt = receipt === undefined
      ? undefined
      : Object.freeze({
        algorithm: receipt.algorithm,
        payload: receipt.payload,
        signatureHash: sha256Version(receipt.signature),
      });
    if (retainedReceipt !== undefined) {
      receiptStatusBySignatureHash.set(retainedReceipt.signatureHash, "UNCONSUMED");
    }
    decisionLog.set(logId, Object.freeze({
      id: logId,
      recordedAt: now,
      principal: retainedPrincipal,
      decision,
      policy,
      ...(actingCredential === undefined ? {} : { actingCredential }),
      ...(grantorCredential === undefined ? {} : { grantorCredential }),
      ...(delegation === undefined ? {} : { delegation }),
      ...(retainedReceipt === undefined ? {} : { receipt: retainedReceipt }),
    }));
    return context.json({ logId, decision, ...(receipt === undefined ? {} : { receipt }) });
  });

  app.post("/step-up/requests", async (context) => {
    const body = await jsonBody(context, ["decisionLogId", "expiresAt"], ["decisionLogId", "expiresAt"]);
    if (typeof body.decisionLogId !== "string") {
      throw new DomainValidationError("decisionLogId is invalid");
    }
    const retained = decisionLog.get(body.decisionLogId);
    if (retained === undefined) {
      return context.json({ error: { code: "DECISION_NOT_FOUND", message: "retained decision was not found" } }, 404);
    }
    if (requestByDecisionLogId.has(body.decisionLogId)) {
      throw new DomainValidationError("step-up request already exists for retained decision");
    }
    const request = stepUpService.createRequest({
      id: options.idFactory("step-up-request"),
      decision: retained.decision,
      expiresAt: body.expiresAt as string,
    });
    requestByDecisionLogId.set(body.decisionLogId, request.id);
    return context.json({ decisionLogId: body.decisionLogId, request }, 201);
  });

  app.post("/step-up/requests/:requestId/resolve", async (context) => {
    const body = await jsonBody(
      context,
      ["resolution", "approver", "approverCredential"],
      ["resolution", "approver", "approverCredential"],
    );
    const result = await stepUpService.resolveRequest({
      requestId: context.req.param("requestId"),
      resolution: body.resolution as "APPROVE" | "REJECT",
      approver: createPrincipal(body.approver),
      approverCredential: body.approverCredential as Credential,
      at: options.clock(),
    });
    if (result.ok) authorizationByRequestId.set(result.authorization.requestId, result.authorization);
    return context.json(result);
  });

  app.post("/step-up/authorizations/consume", async (context) => {
    const directFields = ["authorization", ...stepUpCommonBindingFields, "credentialId"] as const;
    const delegatedFields = [
      "authorization",
      ...stepUpCommonBindingFields,
      ...delegatedBindingFields,
    ] as const;
    const body = await jsonBody(context, [...directFields, ...delegatedFields]);
    const mode = body.authorityMode;
    if (mode !== "DIRECT" && mode !== "DELEGATED") {
      throw new DomainValidationError("authorityMode is required");
    }
    const fields = mode === "DIRECT" ? directFields : delegatedFields;
    exactKeys(body, fields, fields);
    const authorized = await stepUpService.consumeAuthorization({
      ...body,
      authorization: body.authorization as StepUpAuthorization,
      at: options.clock(),
    } as unknown as StepUpAuthorizationBinding & {
      readonly authorization: StepUpAuthorization;
      readonly at: string;
    });
    return context.json({ authorized });
  });

  app.post("/receipts/consume", async (context) => {
    const body = await jsonBody(context, ["receipt", "expected"], ["receipt", "expected"]);
    const expectedRecord = requireRecord(body.expected, "receipt expected binding");
    const mode = expectedRecord.authorityMode;
    if (mode !== "DIRECT" && mode !== "DELEGATED") {
      throw new DomainValidationError("receipt expected authorityMode is required");
    }
    const fields = mode === "DIRECT"
      ? [...receiptCommonBindingFields, "credentialId"]
      : [...receiptCommonBindingFields, ...delegatedBindingFields];
    exactKeys(expectedRecord, fields, fields);
    const result = await verifyAndConsumeReceipt(
      body.receipt,
      receiptHmacKey,
      nonceStore,
      credentialAuthority,
      {
        at: options.clock(),
        expected: expectedRecord as unknown as ReceiptExpectedBinding,
        delegationAuthority,
      },
    );
    const signatureHash = signatureHashFromReceipt(body.receipt);
    if (signatureHash !== undefined && receiptStatusBySignatureHash.has(signatureHash)) {
      const prior = receiptStatusBySignatureHash.get(signatureHash);
      if (result.valid) receiptStatusBySignatureHash.set(signatureHash, "CONSUMED");
      else if (prior !== "CONSUMED") receiptStatusBySignatureHash.set(signatureHash, "REJECTED");
    }
    return context.json(result);
  });

  app.get("/zkya/onboarding-views/:decisionLogId", (context) => {
    if (new URL(context.req.url).searchParams.size > 0) return invalidRequest(context);
    const decisionLogId = context.req.param("decisionLogId");
    const retained = decisionLog.get(decisionLogId);
    if (retained === undefined) {
      return context.json({ error: { code: "DECISION_NOT_FOUND", message: "retained decision was not found" } }, 404);
    }
    const now = options.clock();
    const authority = authoritySnapshot(retained, credentialAuthority, delegationAuthority, now);
    const requestId = requestByDecisionLogId.get(decisionLogId);
    const authorization = requestId === undefined
      ? undefined
      : authorizationByRequestId.get(requestId);
    const approval = currentApproval(
      retained,
      requestId,
      authorization,
      stepUpService,
      now,
    );
    const authorizationUsability = authorization === undefined
      ? undefined
      : stepUpService.inspectAuthorization({ authorization, at: now });
    const receiptStatus = retained.receipt === undefined
      ? "NOT_ISSUED"
      : receiptStatusBySignatureHash.get(retained.receipt.signatureHash) ?? "UNCONSUMED";
    const delegatedScope = retained.decision.authorityMode === "DELEGATED" && retained.delegation !== undefined
      ? {
        delegationId: retained.delegation.id,
        grantorId: retained.delegation.grantorId,
        grantorType: retained.delegation.grantorType,
        capabilities: retained.delegation.capabilities,
        allowedActions: retained.delegation.allowedActions,
        allowedResourceIds: retained.delegation.allowedResourceIds,
        status: authority.delegatedScopeStatus ?? "INVALID",
      }
      : null;
    return context.json({
      version: 1,
      referenceOnly: true,
      decisionLogId,
      verificationStatus: authority.verificationStatus,
      principal: retained.principal,
      authorityMode: retained.decision.authorityMode,
      delegatedScope,
      eligibleActions: [eligibleAction(
        retained,
        authority,
        approval,
        authorizationUsability,
      )],
      requiredApproval: approval,
      receipt: { status: receiptStatus },
      policyId: retained.decision.policyId,
      policyVersion: retained.decision.policyVersion,
    });
  });

  app.get("/decision-log", (context) => context.json({
    referenceOnly: true,
    entries: cloneJson([...decisionLog.values()].map(publicDecisionLogEntry)),
  }));

  return app;
}
