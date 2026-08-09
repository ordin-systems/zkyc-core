import { Hono, type Context } from "hono";
import {
  CredentialAuthority,
  DomainValidationError,
  HumanStepUpService,
  InMemoryAtomicNonceStore,
  createPolicy,
  createPrincipal,
  evaluateAccess,
  sha256Version,
  signReceipt,
  verifyAndConsumeReceipt,
  type AccessDecision,
  type ReceiptExpectedBinding,
  type ReceiptPayload,
  type SignedReceipt,
} from "@ordin/zkyc-core-reference";

export type ReferenceIdKind = "credential" | "decision-log" | "step-up-request" | "receipt-nonce";

export interface ReferenceAppOptions {
  readonly clock: () => string;
  readonly idFactory: (kind: ReferenceIdKind) => string;
  readonly receiptHmacKey: Uint8Array;
  readonly issuerId?: string;
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

const receiptBindingFields = [
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

function invalidRequest(context: Context) {
  return context.json({ error: { code: "INVALID_REQUEST", message: "request body is invalid" } }, 400);
}

export function createReferenceApp(options: ReferenceAppOptions): Hono {
  if (typeof options?.clock !== "function" || typeof options?.idFactory !== "function") {
    throw new DomainValidationError("clock and idFactory are required");
  }
  if (!(options.receiptHmacKey instanceof Uint8Array) || options.receiptHmacKey.byteLength < 32) {
    throw new DomainValidationError("receipt HMAC key must contain at least 32 bytes");
  }

  const receiptHmacKey = new Uint8Array(options.receiptHmacKey);
  const credentialAuthority = new CredentialAuthority({
    issuerId: options.issuerId ?? "issuer:reference-api",
  });
  const nonceStore = new InMemoryAtomicNonceStore();
  const stepUpService = new HumanStepUpService({ credentialAuthority, nonceStore });
  const decisionLog = new Map<string, DecisionLogEntry>();
  const app = new Hono();

  app.use("*", async (context, next) => {
    await next();
    context.header("cache-control", "no-store");
  });

  app.onError((error, context) => {
    if (error instanceof ReferenceHttpError) {
      return context.json({ error: { code: error.code, message: error.message } }, error.status);
    }
    if (error instanceof DomainValidationError || error instanceof SyntaxError) return invalidRequest(context);
    return context.json({ error: { code: "INTERNAL_ERROR", message: "reference adapter failed closed" } }, 500);
  });

  app.get("/health", (context) => context.json({
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.2.0",
    state: "in-memory-reference-only",
  }));

  app.post("/credentials", async (context) => {
    const body = await jsonBody(
      context,
      ["principal", "capabilities", "expiresAt", "unverifiedMetadata"],
      ["principal", "capabilities", "expiresAt"],
    );
    const now = options.clock();
    const principal = createPrincipal(body.principal);
    const input = {
      id: options.idFactory("credential"),
      principal,
      capabilities: body.capabilities as readonly string[],
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

  app.post("/evaluations", async (context) => {
    const body = await jsonBody(
      context,
      [
        "principal",
        "credential",
        "action",
        "resourceId",
        "actionContext",
        "policy",
        "issueReceipt",
        "receiptExpiresAt",
      ],
      ["principal", "credential", "action", "resourceId", "actionContext", "policy", "issueReceipt"],
    );
    if (typeof body.issueReceipt !== "boolean") throw new DomainValidationError("issueReceipt must be boolean");
    const now = options.clock();
    const policy = createPolicy(body.policy);
    const decision = evaluateAccess({
      principal: body.principal,
      credential: body.credential,
      action: body.action,
      resourceId: body.resourceId,
      actionContext: body.actionContext,
      policy,
      at: now,
      credentialAuthority,
    });
    const logId = options.idFactory("decision-log");
    let receipt: SignedReceipt | undefined;
    if (body.issueReceipt && decision.outcome === "ALLOW") {
      if (body.receiptExpiresAt === undefined || decision.credentialId === undefined) {
        throw new DomainValidationError("receipt expiry is required for ALLOW receipt issuance");
      }
      const payload: ReceiptPayload = {
        version: 1,
        subjectId: decision.subjectId,
        action: decision.action,
        actionSensitivity: decision.actionSensitivity,
        resourceId: decision.resourceId,
        contextHash: decision.contextHash,
        policyId: decision.policyId,
        policyVersion: decision.policyVersion,
        credentialId: decision.credentialId,
        decision: decision.outcome,
        reasonCode: decision.reasonCode,
        nonce: options.idFactory("receipt-nonce"),
        decidedAt: decision.decidedAt,
        issuedAt: now,
        expiresAt: body.receiptExpiresAt as string,
      };
      receipt = signReceipt(payload, receiptHmacKey);
    }
    decisionLog.set(logId, Object.freeze({
      id: logId,
      recordedAt: now,
      decision,
      ...(receipt === undefined
        ? {}
        : {
            receipt: Object.freeze({
              algorithm: receipt.algorithm,
              payload: receipt.payload,
              signatureHash: sha256Version(receipt.signature),
            }),
          }),
    }));
    return context.json({ logId, decision, ...(receipt === undefined ? {} : { receipt }) });
  });

  app.post("/step-up/requests", async (context) => {
    const body = await jsonBody(context, ["decisionLogId", "expiresAt"], ["decisionLogId", "expiresAt"]);
    if (typeof body.decisionLogId !== "string") throw new DomainValidationError("decisionLogId is invalid");
    const retained = decisionLog.get(body.decisionLogId);
    if (retained === undefined) {
      return context.json({ error: { code: "DECISION_NOT_FOUND", message: "retained decision was not found" } }, 404);
    }
    const request = stepUpService.createRequest({
      id: options.idFactory("step-up-request"),
      decision: retained.decision,
      expiresAt: body.expiresAt as string,
    });
    return context.json({ request }, 201);
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
      approverCredential: body.approverCredential as never,
      at: options.clock(),
    });
    return context.json(result);
  });

  app.post("/step-up/authorizations/consume", async (context) => {
    const allowed = [
      "authorization",
      "subjectId",
      "action",
      "actionSensitivity",
      "resourceId",
      "contextHash",
      "policyId",
      "policyVersion",
      "credentialId",
    ] as const;
    const body = await jsonBody(context, allowed, allowed);
    const authorized = await stepUpService.consumeAuthorization({
      authorization: body.authorization as never,
      subjectId: body.subjectId as string,
      action: body.action as string,
      actionSensitivity: body.actionSensitivity as never,
      resourceId: body.resourceId as string,
      contextHash: body.contextHash as string,
      policyId: body.policyId as string,
      policyVersion: body.policyVersion as string,
      credentialId: body.credentialId as string,
      at: options.clock(),
    });
    return context.json({ authorized });
  });

  app.post("/receipts/consume", async (context) => {
    const body = await jsonBody(context, ["receipt", "expected"], ["receipt", "expected"]);
    const expectedRecord = requireRecord(body.expected, "receipt expected binding");
    exactKeys(expectedRecord, receiptBindingFields, receiptBindingFields);
    const result = await verifyAndConsumeReceipt(
      body.receipt,
      receiptHmacKey,
      nonceStore,
      credentialAuthority,
      { at: options.clock(), expected: expectedRecord as unknown as ReceiptExpectedBinding },
    );
    return context.json(result);
  });

  app.get("/decision-log", (context) => context.json({
    referenceOnly: true,
    entries: cloneJson([...decisionLog.values()]),
  }));

  return app;
}
