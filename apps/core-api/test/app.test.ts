import assert from "node:assert/strict";
import test from "node:test";
import {
  ActionSensitivity,
  PrincipalType,
  type AccessDecision,
  type CapabilityDelegation,
  type Credential,
  type ReceiptExpectedBinding,
  type SignedReceipt,
  type StepUpAuthorization,
} from "@ordin/zkyc-core-reference";
import { createReferenceApp } from "../src/app.js";

const TEST_SECRET = "0123456789abcdef0123456789abcdef";
const TEST_KEY = new TextEncoder().encode(TEST_SECRET);
const START = "2026-06-01T00:10:00.000Z";
const LATER = "2026-06-01T00:11:00.000Z";
const EXPIRY = "2026-06-01T01:00:00.000Z";
const RECEIPT_EXPIRY = "2026-06-01T00:20:00.000Z";
const RESOURCE = "record:customer-7";
const MEMBER = { organizationId: "organization:fixture", role: "member" } as const;

type JsonRecord = Record<string, unknown>;

interface OnboardingView {
  readonly version: 1;
  readonly referenceOnly: true;
  readonly decisionLogId: string;
  readonly verificationStatus: "ACTIVE" | "REVOKED" | "EXPIRED" | "INVALID";
  readonly principal: {
    readonly id: string;
    readonly type: PrincipalType;
    readonly affiliations: readonly typeof MEMBER[];
  };
  readonly authorityMode: "DIRECT" | "DELEGATED";
  readonly delegatedScope: null | {
    readonly delegationId: string;
    readonly grantorId: string;
    readonly grantorType: PrincipalType;
    readonly capabilities: readonly string[];
    readonly allowedActions: readonly string[];
    readonly allowedResourceIds: readonly string[];
    readonly status: "ACTIVE" | "REVOKED" | "EXPIRED" | "INVALID";
  };
  readonly eligibleActions: readonly {
    readonly action: string;
    readonly resourceId: string;
    readonly status: "ELIGIBLE" | "APPROVAL_REQUIRED" | "INELIGIBLE";
    readonly reasonCode: string;
  }[];
  readonly requiredApproval: {
    readonly status: "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
    readonly requestId?: string;
  };
  readonly receipt: {
    readonly status: "NOT_ISSUED" | "UNCONSUMED" | "CONSUMED" | "REJECTED";
  };
  readonly policyId: string;
  readonly policyVersion: string;
}

function harness() {
  let now = START;
  const counters = new Map<string, number>();
  const app = createReferenceApp({
    clock: () => now,
    idFactory: (kind) => {
      const next = (counters.get(kind) ?? 0) + 1;
      counters.set(kind, next);
      return `${kind}:${next}`;
    },
    receiptHmacKey: TEST_KEY,
    trustedPolicies: [policy("ALLOW"), policy("DENY"), policy("STEP_UP")],
    issuerId: "issuer:reference-api-test",
  });
  return {
    app,
    setNow(value: string) {
      now = value;
    },
  };
}

async function requestJson(
  app: ReturnType<typeof createReferenceApp>,
  path: string,
  options: { method?: string; body?: unknown; rawBody?: string; contentType?: string } = {},
) {
  const requestBody = options.rawBody ??
    (options.body === undefined ? undefined : JSON.stringify(options.body));
  const init: RequestInit = {
    method: options.method ?? "GET",
    ...(requestBody === undefined
      ? {}
      : {
        headers: { "content-type": options.contentType ?? "application/json" },
        body: requestBody,
      }),
  };
  const response = await app.request(path, init);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return { response, body };
}

function principalFor(credential: Credential) {
  return {
    id: credential.principalId,
    type: credential.principalType,
    affiliations: credential.affiliations,
  };
}

async function issueCredential(
  app: ReturnType<typeof createReferenceApp>,
  input: {
    principalId?: string;
    principalType?: PrincipalType;
    affiliations?: readonly typeof MEMBER[];
    capabilities?: readonly string[];
    allowedActions?: readonly string[];
    allowedResourceIds?: readonly string[];
    expiresAt?: string;
  } = {},
): Promise<Credential> {
  const result = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: {
        id: input.principalId ?? "principal:alice",
        type: input.principalType ?? PrincipalType.HUMAN,
        affiliations: input.affiliations ?? [MEMBER],
      },
      capabilities: input.capabilities ?? ["records:read", "records:export"],
      allowedActions: input.allowedActions ?? ["records:read", "records:export"],
      allowedResourceIds: input.allowedResourceIds ?? [RESOURCE],
      expiresAt: input.expiresAt ?? EXPIRY,
    },
  });
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  return (result.body as { credential: Credential }).credential;
}

function policy(
  effect: "ALLOW" | "DENY" | "STEP_UP",
  action = effect === "STEP_UP" ? "records:export" : "records:read",
) {
  return {
    id: `policy:${effect.toLowerCase()}:${action.replaceAll(":", "-")}`,
    rules: [{
      action,
      actionSensitivity: effect === "STEP_UP"
        ? ActionSensitivity.SENSITIVE
        : ActionSensitivity.ROUTINE,
      requiredCapabilities: [action],
      requiredAffiliations: [MEMBER],
      effect,
      ...(effect === "STEP_UP"
        ? { approverCapability: "approval:records-export" }
        : {}),
    }],
  };
}

async function evaluateDirect(
  app: ReturnType<typeof createReferenceApp>,
  credential: Credential,
  input: {
    effect?: "ALLOW" | "DENY" | "STEP_UP";
    action?: string;
    issueReceipt?: boolean;
  } = {},
) {
  const effect = input.effect ?? "ALLOW";
  const action = input.action ?? (effect === "STEP_UP" ? "records:export" : "records:read");
  return requestJson(app, "/evaluations", {
    method: "POST",
    body: {
      authorityMode: "DIRECT",
      principal: principalFor(credential),
      credential,
      action,
      resourceId: RESOURCE,
      actionContext: { fields: ["status"], purpose: "review" },
      policy: policy(effect, action),
      issueReceipt: input.issueReceipt ?? true,
      ...((input.issueReceipt ?? true) ? { receiptExpiresAt: RECEIPT_EXPIRY } : {}),
    },
  });
}

async function issueDelegation(
  app: ReturnType<typeof createReferenceApp>,
  grantorCredential: Credential,
  delegateCredential: Credential,
  input: {
    effect?: "ALLOW" | "STEP_UP";
    action?: string;
    expiresAt?: string;
  } = {},
): Promise<CapabilityDelegation> {
  const effect = input.effect ?? "ALLOW";
  const action = input.action ?? (effect === "STEP_UP" ? "records:export" : "records:read");
  const result = await requestJson(app, "/delegations", {
    method: "POST",
    body: {
      grantor: principalFor(grantorCredential),
      grantorCredential,
      delegate: principalFor(delegateCredential),
      policy: policy(effect, action),
      capabilities: [action],
      allowedActions: [action],
      allowedResourceIds: [RESOURCE],
      expiresAt: input.expiresAt ?? RECEIPT_EXPIRY,
    },
  });
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  return (result.body as { delegation: CapabilityDelegation }).delegation;
}

async function evaluateDelegated(
  app: ReturnType<typeof createReferenceApp>,
  delegateIdentityCredential: Credential,
  grantorCredential: Credential,
  delegation: CapabilityDelegation,
  input: {
    effect?: "ALLOW" | "STEP_UP";
    action?: string;
    issueReceipt?: boolean;
  } = {},
) {
  const effect = input.effect ?? "ALLOW";
  const action = input.action ?? (effect === "STEP_UP" ? "records:export" : "records:read");
  return requestJson(app, "/evaluations", {
    method: "POST",
    body: {
      authorityMode: "DELEGATED",
      principal: principalFor(delegateIdentityCredential),
      delegateIdentityCredential,
      grantorCredential,
      delegation,
      action,
      resourceId: RESOURCE,
      actionContext: { fields: ["status"], purpose: "delegated-review" },
      policy: policy(effect, action),
      issueReceipt: input.issueReceipt ?? true,
      ...((input.issueReceipt ?? true) ? { receiptExpiresAt: RECEIPT_EXPIRY } : {}),
    },
  });
}

function receiptExpectedBinding(decision: AccessDecision): ReceiptExpectedBinding {
  assert.ok(decision.authorityMode);
  assert.ok(decision.subjectType);
  assert.ok(decision.actingCredentialId);
  assert.ok(decision.effectiveScopeHash);
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
    assert.ok(decision.credentialId);
    return { ...common, authorityMode: "DIRECT", credentialId: decision.credentialId };
  }
  assert.ok(decision.grantorId);
  assert.ok(decision.grantorType);
  assert.ok(decision.grantorCredentialId);
  assert.ok(decision.delegationId);
  assert.ok(decision.delegationBindingHash);
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: decision.grantorId,
    grantorType: decision.grantorType,
    grantorCredentialId: decision.grantorCredentialId,
    delegationId: decision.delegationId,
    delegationBindingHash: decision.delegationBindingHash,
  };
}

function authorizationConsumeBody(authorization: StepUpAuthorization): JsonRecord {
  const {
    version: _version,
    id: _id,
    issuedAt: _issuedAt,
    expiresAt: _expiresAt,
    ...binding
  } = authorization;
  return { authorization, ...binding } as JsonRecord;
}

async function onboarding(
  app: ReturnType<typeof createReferenceApp>,
  decisionLogId: string,
): Promise<OnboardingView> {
  const result = await requestJson(
    app,
    `/zkya/onboarding-views/${encodeURIComponent(decisionLogId)}`,
  );
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  return result.body as OnboardingView;
}

async function issueApprover(
  app: ReturnType<typeof createReferenceApp>,
  expiresAt = EXPIRY,
): Promise<Credential> {
  return issueCredential(app, {
    principalId: "principal:approver",
    principalType: PrincipalType.HUMAN,
    capabilities: ["approval:records-export"],
    allowedActions: ["step-up:resolve"],
    allowedResourceIds: [RESOURCE],
    expiresAt,
  });
}

async function createStepUpRequest(
  app: ReturnType<typeof createReferenceApp>,
  decisionLogId: string,
) {
  const result = await requestJson(app, "/step-up/requests", {
    method: "POST",
    body: { decisionLogId, expiresAt: RECEIPT_EXPIRY },
  });
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  assert.deepEqual(Object.keys(result.body as JsonRecord).sort(), ["decisionLogId", "request"]);
  assert.equal((result.body as JsonRecord).decisionLogId, decisionLogId);
  return (result.body as { decisionLogId: string; request: { id: string } }).request;
}

async function delegatedArtifacts(
  app: ReturnType<typeof createReferenceApp>,
  effect: "ALLOW" | "STEP_UP" = "ALLOW",
  expiresAt = RECEIPT_EXPIRY,
) {
  const action = effect === "STEP_UP" ? "records:export" : "records:read";
  const grantorCredential = await issueCredential(app, {
    principalId: "organization:grantor",
    principalType: PrincipalType.ORGANIZATION,
    capabilities: [action],
    allowedActions: [action],
    allowedResourceIds: [RESOURCE],
  });
  const delegateIdentityCredential = await issueCredential(app, {
    principalId: "agent:delegate",
    principalType: PrincipalType.AGENT,
    capabilities: ["identity:act"],
    allowedActions: [action],
    allowedResourceIds: [RESOURCE],
  });
  const delegation = await issueDelegation(
    app,
    grantorCredential,
    delegateIdentityCredential,
    { effect, action, expiresAt },
  );
  return { action, grantorCredential, delegateIdentityCredential, delegation };
}

test("health and direct v2 authority lifecycle expose a deterministic onboarding view", async () => {
  const { app } = harness();
  const health = await requestJson(app, "/health");
  assert.deepEqual(health.body, {
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.3.0",
    state: "in-memory-reference-only",
  });

  const credential = await issueCredential(app);
  assert.equal(credential.version, 2);
  assert.equal(credential.principalType, PrincipalType.HUMAN);
  assert.deepEqual(credential.allowedActions, ["records:export", "records:read"]);
  assert.deepEqual(credential.allowedResourceIds, [RESOURCE]);

  const evaluated = await evaluateDirect(app, credential);
  assert.equal(evaluated.response.status, 200);
  const output = evaluated.body as {
    logId: string;
    decision: AccessDecision;
    receipt: SignedReceipt;
  };
  assert.equal(output.decision.outcome, "ALLOW");
  assert.equal(output.decision.authorityMode, "DIRECT");
  assert.equal(output.receipt.payload.version, 2);
  assert.equal(output.receipt.payload.subjectType, PrincipalType.HUMAN);
  assert.equal(output.receipt.payload.effectiveScopeHash, credential.scopeHash);

  const initial = await onboarding(app, output.logId);
  assert.equal(initial.version, 1);
  assert.equal(initial.referenceOnly, true);
  assert.equal(initial.verificationStatus, "ACTIVE");
  assert.deepEqual(initial.principal, principalFor(credential));
  assert.equal(initial.authorityMode, "DIRECT");
  assert.equal(initial.delegatedScope, null);
  assert.deepEqual(initial.eligibleActions, [{
    action: "records:read",
    resourceId: RESOURCE,
    status: "ELIGIBLE",
    reasonCode: "POLICY_ALLOW",
  }]);
  assert.deepEqual(initial.requiredApproval, { status: "NOT_REQUIRED" });
  assert.deepEqual(initial.receipt, { status: "UNCONSUMED" });

  const expected = receiptExpectedBinding(output.decision);
  const rejected = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected: { ...expected, resourceId: "record:other" } },
  });
  assert.deepEqual(rejected.body, { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" });
  assert.deepEqual((await onboarding(app, output.logId)).receipt, { status: "REJECTED" });

  const consumed = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected },
  });
  assert.deepEqual(consumed.body, { valid: true, reasonCode: "RECEIPT_VALID" });
  assert.deepEqual((await onboarding(app, output.logId)).receipt, { status: "CONSUMED" });

  const replay = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected },
  });
  assert.deepEqual(replay.body, { valid: false, reasonCode: "RECEIPT_REPLAYED" });
  assert.deepEqual((await onboarding(app, output.logId)).receipt, { status: "CONSUMED" });
});

test("direct onboarding refresh reflects credential revocation and expiry", async () => {
  const revokedHarness = harness();
  const credential = await issueCredential(revokedHarness.app);
  const evaluated = await evaluateDirect(revokedHarness.app, credential, { issueReceipt: false });
  const logId = (evaluated.body as { logId: string }).logId;
  const revocation = await requestJson(
    revokedHarness.app,
    `/credentials/${encodeURIComponent(credential.id)}/revoke`,
    { method: "POST", body: { reason: "reference-test" } },
  );
  assert.deepEqual(revocation.body, { revoked: true });
  const revoked = await onboarding(revokedHarness.app, logId);
  assert.equal(revoked.verificationStatus, "REVOKED");
  assert.equal(revoked.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(revoked.eligibleActions[0]?.reasonCode, "CREDENTIAL_REVOKED");

  const expiredHarness = harness();
  const expiring = await issueCredential(expiredHarness.app, {
    expiresAt: "2026-06-01T00:12:00.000Z",
  });
  const expiringDecision = await evaluateDirect(expiredHarness.app, expiring, {
    issueReceipt: false,
  });
  const expiringLogId = (expiringDecision.body as { logId: string }).logId;
  expiredHarness.setNow("2026-06-01T00:12:00.000Z");
  const expired = await onboarding(expiredHarness.app, expiringLogId);
  assert.equal(expired.verificationStatus, "EXPIRED");
  assert.equal(expired.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(expired.eligibleActions[0]?.reasonCode, "CREDENTIAL_EXPIRED");
});

test("delegation issuance, delegated receipt consumption, and revocation stay authority-bound", async () => {
  const { app, setNow } = harness();
  const artifacts = await delegatedArtifacts(app);
  assert.equal(artifacts.delegation.issuerId, artifacts.grantorCredential.issuerId);
  assert.equal(artifacts.delegation.grantorCredentialId, artifacts.grantorCredential.id);
  assert.equal(artifacts.delegation.delegateType, PrincipalType.AGENT);
  assert.deepEqual(artifacts.delegation.capabilities, ["records:read"]);

  const substitutedGrantor = await requestJson(app, "/delegations", {
    method: "POST",
    body: {
      grantor: {
        ...principalFor(artifacts.grantorCredential),
        affiliations: [{ organizationId: "organization:forged", role: "admin" }],
      },
      grantorCredential: artifacts.grantorCredential,
      delegate: principalFor(artifacts.delegateIdentityCredential),
      policy: policy("ALLOW", "records:read"),
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: RECEIPT_EXPIRY,
    },
  });
  assert.equal(substitutedGrantor.response.status, 400);
  assert.deepEqual(substitutedGrantor.body, {
    error: {
      code: "DELEGATION_GRANTOR_MISMATCH",
      message: "delegation request is invalid",
    },
  });

  const evaluated = await evaluateDelegated(
    app,
    artifacts.delegateIdentityCredential,
    artifacts.grantorCredential,
    artifacts.delegation,
  );
  assert.equal(evaluated.response.status, 200);
  const output = evaluated.body as {
    logId: string;
    decision: AccessDecision;
    receipt: SignedReceipt;
  };
  assert.equal(output.decision.outcome, "ALLOW");
  assert.equal(output.decision.authorityMode, "DELEGATED");
  assert.equal(output.decision.actingCredentialId, artifacts.delegateIdentityCredential.id);
  assert.equal(output.decision.grantorCredentialId, artifacts.grantorCredential.id);
  assert.equal(output.decision.delegationId, artifacts.delegation.id);
  assert.equal(output.receipt.payload.authorityMode, "DELEGATED");

  const initial = await onboarding(app, output.logId);
  assert.equal(initial.verificationStatus, "ACTIVE");
  assert.equal(initial.principal.id, artifacts.delegateIdentityCredential.principalId);
  assert.equal(initial.principal.type, PrincipalType.AGENT);
  assert.deepEqual(initial.delegatedScope, {
    delegationId: artifacts.delegation.id,
    grantorId: artifacts.grantorCredential.principalId,
    grantorType: PrincipalType.ORGANIZATION,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
    status: "ACTIVE",
  });

  const consumed = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: {
      receipt: output.receipt,
      expected: receiptExpectedBinding(output.decision),
    },
  });
  assert.deepEqual(consumed.body, { valid: true, reasonCode: "RECEIPT_VALID" });
  assert.equal((await onboarding(app, output.logId)).receipt.status, "CONSUMED");

  setNow(LATER);
  const revoked = await requestJson(
    app,
    `/delegations/${encodeURIComponent(artifacts.delegation.id)}/revoke`,
    { method: "POST", body: { reason: "scope-withdrawn" } },
  );
  assert.deepEqual(revoked.body, { revoked: true });
  const refreshed = await onboarding(app, output.logId);
  assert.equal(refreshed.verificationStatus, "REVOKED");
  assert.equal(refreshed.delegatedScope?.status, "REVOKED");
  assert.equal(refreshed.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(refreshed.eligibleActions[0]?.reasonCode, "DELEGATION_REVOKED");
  assert.equal(refreshed.receipt.status, "CONSUMED");
});

test("delegated onboarding refresh reflects delegation expiry", async () => {
  const { app, setNow } = harness();
  const delegationExpiry = "2026-06-01T00:12:00.000Z";
  const artifacts = await delegatedArtifacts(app, "ALLOW", delegationExpiry);
  const evaluated = await evaluateDelegated(
    app,
    artifacts.delegateIdentityCredential,
    artifacts.grantorCredential,
    artifacts.delegation,
    { issueReceipt: false },
  );
  const logId = (evaluated.body as { logId: string }).logId;
  setNow(delegationExpiry);
  const view = await onboarding(app, logId);
  assert.equal(view.verificationStatus, "EXPIRED");
  assert.equal(view.delegatedScope?.status, "EXPIRED");
  assert.equal(view.eligibleActions[0]?.reasonCode, "DELEGATION_EXPIRED");
});

test("direct step-up state refreshes through pending, approval, and one-time consumption", async () => {
  const { app, setNow } = harness();
  const subject = await issueCredential(app, {
    capabilities: ["records:export"],
    allowedActions: ["records:export"],
  });
  const evaluated = await evaluateDirect(app, subject, {
    effect: "STEP_UP",
    action: "records:export",
  });
  const output = evaluated.body as { logId: string; decision: AccessDecision };
  assert.equal(output.decision.outcome, "STEP_UP");
  assert.equal((await onboarding(app, output.logId)).requiredApproval.status, "PENDING");

  const request = await createStepUpRequest(app, output.logId);
  const pending = await onboarding(app, output.logId);
  assert.deepEqual(pending.requiredApproval, { status: "PENDING", requestId: request.id });
  assert.equal(pending.eligibleActions[0]?.status, "APPROVAL_REQUIRED");

  const approverCredential = await issueApprover(app);
  setNow(LATER);
  const resolved = await requestJson(
    app,
    `/step-up/requests/${encodeURIComponent(request.id)}/resolve`,
    {
      method: "POST",
      body: {
        resolution: "APPROVE",
        approver: principalFor(approverCredential),
        approverCredential,
      },
    },
  );
  assert.equal(resolved.response.status, 200);
  const authorization = (resolved.body as { ok: true; authorization: StepUpAuthorization })
    .authorization;
  const approved = await onboarding(app, output.logId);
  assert.deepEqual(approved.requiredApproval, { status: "APPROVED", requestId: request.id });
  assert.equal(approved.eligibleActions[0]?.status, "ELIGIBLE");
  assert.equal(approved.eligibleActions[0]?.reasonCode, "STEP_UP_APPROVED");

  const binding = authorizationConsumeBody(authorization);
  const consumed = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: binding,
  });
  assert.deepEqual(consumed.body, { authorized: true });
  const consumedView = await onboarding(app, output.logId);
  assert.deepEqual(consumedView.requiredApproval, {
    status: "APPROVED",
    requestId: request.id,
  });
  assert.equal(consumedView.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(
    consumedView.eligibleActions[0]?.reasonCode,
    "STEP_UP_AUTHORIZATION_CONSUMED",
  );
  const replay = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: binding,
  });
  assert.deepEqual(replay.body, { authorized: false });
  const replayView = await onboarding(app, output.logId);
  assert.equal(replayView.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(
    replayView.eligibleActions[0]?.reasonCode,
    "STEP_UP_AUTHORIZATION_CONSUMED",
  );

  setNow(RECEIPT_EXPIRY);
  const expiredAuthorizationView = await onboarding(app, output.logId);
  assert.equal(expiredAuthorizationView.requiredApproval.status, "EXPIRED");
  assert.equal(expiredAuthorizationView.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(expiredAuthorizationView.eligibleActions[0]?.reasonCode, "STEP_UP_EXPIRED");
});

test("delegated step-up consume requires and honors every delegated v2 binding", async () => {
  const { app, setNow } = harness();
  const artifacts = await delegatedArtifacts(app, "STEP_UP");
  const evaluated = await evaluateDelegated(
    app,
    artifacts.delegateIdentityCredential,
    artifacts.grantorCredential,
    artifacts.delegation,
    { effect: "STEP_UP", action: "records:export" },
  );
  const output = evaluated.body as { logId: string; decision: AccessDecision };
  assert.equal(output.decision.outcome, "STEP_UP");
  const request = await createStepUpRequest(app, output.logId);
  const approverCredential = await issueApprover(app);
  setNow(LATER);
  const resolved = await requestJson(
    app,
    `/step-up/requests/${encodeURIComponent(request.id)}/resolve`,
    {
      method: "POST",
      body: {
        resolution: "APPROVE",
        approver: principalFor(approverCredential),
        approverCredential,
      },
    },
  );
  const authorization = (resolved.body as { ok: true; authorization: StepUpAuthorization })
    .authorization;
  assert.equal(authorization.authorityMode, "DELEGATED");
  const complete = authorizationConsumeBody(authorization);
  const { delegationBindingHash: _removed, ...incomplete } = complete;
  const rejected = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: incomplete,
  });
  assert.equal(rejected.response.status, 400);

  const consumed = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: complete,
  });
  assert.deepEqual(consumed.body, { authorized: true });
  const consumedView = await onboarding(app, output.logId);
  assert.equal(consumedView.requiredApproval.status, "APPROVED");
  assert.equal(consumedView.eligibleActions[0]?.status, "INELIGIBLE");
  assert.equal(
    consumedView.eligibleActions[0]?.reasonCode,
    "STEP_UP_AUTHORIZATION_CONSUMED",
  );
});

test("direct step-up refresh revalidates approver revocation and expiry", async () => {
  for (const invalidation of ["revoked", "expired"] as const) {
    const { app, setNow } = harness();
    const subject = await issueCredential(app, {
      capabilities: ["records:export"],
      allowedActions: ["records:export"],
    });
    const evaluated = await evaluateDirect(app, subject, {
      effect: "STEP_UP",
      action: "records:export",
    });
    const output = evaluated.body as { logId: string; decision: AccessDecision };
    const request = await createStepUpRequest(app, output.logId);
    const approverExpiry = invalidation === "expired"
      ? "2026-06-01T00:12:00.000Z"
      : EXPIRY;
    const approverCredential = await issueApprover(app, approverExpiry);
    setNow(LATER);
    const resolved = await requestJson(
      app,
      `/step-up/requests/${encodeURIComponent(request.id)}/resolve`,
      {
        method: "POST",
        body: {
          resolution: "APPROVE",
          approver: principalFor(approverCredential),
          approverCredential,
        },
      },
    );
    assert.equal((resolved.body as { ok: boolean }).ok, true);

    if (invalidation === "revoked") {
      const revoked = await requestJson(
        app,
        `/credentials/${encodeURIComponent(approverCredential.id)}/revoke`,
        { method: "POST", body: { reason: "approver-authority-withdrawn" } },
      );
      assert.deepEqual(revoked.body, { revoked: true });
    } else {
      setNow(approverExpiry);
    }

    const refreshed = await onboarding(app, output.logId);
    assert.equal(refreshed.eligibleActions[0]?.status, "INELIGIBLE");
    assert.equal(
      refreshed.eligibleActions[0]?.reasonCode,
      invalidation === "revoked"
        ? "APPROVER_CREDENTIAL_REVOKED"
        : "APPROVER_CREDENTIAL_EXPIRED",
    );
  }
});

test("delegated step-up refresh revalidates retained subject and approver authority", async () => {
  for (const invalidation of ["acting", "grantor", "delegation", "approver"] as const) {
    const { app, setNow } = harness();
    const artifacts = await delegatedArtifacts(app, "STEP_UP");
    const evaluated = await evaluateDelegated(
      app,
      artifacts.delegateIdentityCredential,
      artifacts.grantorCredential,
      artifacts.delegation,
      { effect: "STEP_UP", action: "records:export" },
    );
    const output = evaluated.body as { logId: string; decision: AccessDecision };
    const request = await createStepUpRequest(app, output.logId);
    const approverCredential = await issueApprover(app);
    setNow(LATER);
    const resolved = await requestJson(
      app,
      `/step-up/requests/${encodeURIComponent(request.id)}/resolve`,
      {
        method: "POST",
        body: {
          resolution: "APPROVE",
          approver: principalFor(approverCredential),
          approverCredential,
        },
      },
    );
    assert.equal((resolved.body as { ok: boolean }).ok, true);

    if (invalidation === "delegation") {
      await requestJson(
        app,
        `/delegations/${encodeURIComponent(artifacts.delegation.id)}/revoke`,
        { method: "POST", body: { reason: "delegated-authority-withdrawn" } },
      );
    } else {
      const credentialId = invalidation === "acting"
        ? artifacts.delegateIdentityCredential.id
        : invalidation === "grantor"
        ? artifacts.grantorCredential.id
        : approverCredential.id;
      await requestJson(app, `/credentials/${encodeURIComponent(credentialId)}/revoke`, {
        method: "POST",
        body: { reason: `${invalidation}-authority-withdrawn` },
      });
    }

    const refreshed = await onboarding(app, output.logId);
    assert.equal(refreshed.eligibleActions[0]?.status, "INELIGIBLE");
    assert.equal(
      refreshed.eligibleActions[0]?.reasonCode,
      invalidation === "delegation"
        ? "DELEGATION_REVOKED"
        : invalidation === "approver"
        ? "APPROVER_CREDENTIAL_REVOKED"
        : "CREDENTIAL_REVOKED",
    );
  }
});

test("step-up rejection and expiry are visible on onboarding refresh", async () => {
  const rejectedHarness = harness();
  const subject = await issueCredential(rejectedHarness.app, {
    capabilities: ["records:export"],
    allowedActions: ["records:export"],
  });
  const evaluated = await evaluateDirect(rejectedHarness.app, subject, {
    effect: "STEP_UP",
    action: "records:export",
  });
  const logId = (evaluated.body as { logId: string }).logId;
  const request = await createStepUpRequest(rejectedHarness.app, logId);
  const approver = await issueApprover(rejectedHarness.app);
  rejectedHarness.setNow(LATER);
  const rejected = await requestJson(
    rejectedHarness.app,
    `/step-up/requests/${encodeURIComponent(request.id)}/resolve`,
    {
      method: "POST",
      body: {
        resolution: "REJECT",
        approver: principalFor(approver),
        approverCredential: approver,
      },
    },
  );
  assert.deepEqual(rejected.body, { ok: false, reasonCode: "STEP_UP_REJECTED" });
  const rejectedView = await onboarding(rejectedHarness.app, logId);
  assert.equal(rejectedView.requiredApproval.status, "REJECTED");
  assert.equal(rejectedView.eligibleActions[0]?.status, "INELIGIBLE");

  const expiredHarness = harness();
  const expiringSubject = await issueCredential(expiredHarness.app, {
    capabilities: ["records:export"],
    allowedActions: ["records:export"],
  });
  const expiringEvaluation = await evaluateDirect(expiredHarness.app, expiringSubject, {
    effect: "STEP_UP",
    action: "records:export",
  });
  const expiringLogId = (expiringEvaluation.body as { logId: string }).logId;
  await createStepUpRequest(expiredHarness.app, expiringLogId);
  expiredHarness.setNow(RECEIPT_EXPIRY);
  const expiredView = await onboarding(expiredHarness.app, expiringLogId);
  assert.equal(expiredView.requiredApproval.status, "EXPIRED");
  assert.equal(expiredView.eligibleActions[0]?.reasonCode, "STEP_UP_EXPIRED");
});

test("strict transport rejects unknown or incomplete fields and never leaks signing material", async () => {
  const { app } = harness();
  const missingType = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: { id: "principal:alice", affiliations: [] },
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: EXPIRY,
    },
  });
  assert.equal(missingType.response.status, 400);

  const missingScope = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: { id: "principal:alice", type: PrincipalType.HUMAN, affiliations: [] },
      capabilities: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: EXPIRY,
    },
  });
  assert.equal(missingScope.response.status, 400);

  const unknown = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: {
        id: "principal:alice",
        type: PrincipalType.HUMAN,
        affiliations: [],
        elevated: true,
      },
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: EXPIRY,
    },
  });
  assert.equal(unknown.response.status, 400);

  const malformed = await requestJson(app, "/evaluations", {
    method: "POST",
    rawBody: "{not-json",
  });
  assert.equal(malformed.response.status, 400);

  const credential = await issueCredential(app);
  const mixedMode = await requestJson(app, "/evaluations", {
    method: "POST",
    body: {
      authorityMode: "DIRECT",
      principal: principalFor(credential),
      credential,
      delegateIdentityCredential: credential,
      action: "records:read",
      resourceId: RESOURCE,
      actionContext: {},
      policy: policy("ALLOW"),
      issueReceipt: false,
    },
  });
  assert.equal(mixedMode.response.status, 400);

  const unknownDelegationField = await requestJson(app, "/delegations", {
    method: "POST",
    body: { unexpected: true },
  });
  assert.equal(unknownDelegationField.response.status, 400);

  const evaluated = await evaluateDirect(app, credential);
  const output = evaluated.body as {
    logId: string;
    decision: AccessDecision;
    receipt: SignedReceipt;
  };
  const expected = receiptExpectedBinding(output.decision);
  const { policyVersion: _removedPolicyVersion, ...incompleteExpected } = expected;
  const incompleteReceipt = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected: incompleteExpected },
  });
  assert.equal(incompleteReceipt.response.status, 400);

  const callerStatus = await requestJson(
    app,
    `/zkya/onboarding-views/${encodeURIComponent(output.logId)}?status=ACTIVE`,
  );
  assert.equal(callerStatus.response.status, 400);
  const missingView = await requestJson(app, "/zkya/onboarding-views/decision-log:missing");
  assert.equal(missingView.response.status, 404);

  for (const contentType of ["application/jsonp", "foo/application/json", "text/plain"]) {
    const rejected = await requestJson(app, "/credentials", {
      method: "POST",
      contentType,
      body: {
        principal: {
          id: "principal:media",
          type: PrincipalType.HUMAN,
          affiliations: [],
        },
        capabilities: [],
        allowedActions: [],
        allowedResourceIds: [],
        expiresAt: EXPIRY,
      },
    });
    assert.equal(rejected.response.status, 415);
    assert.equal(rejected.response.headers.get("cache-control"), "no-store");
  }

  const log = await requestJson(app, "/decision-log");
  const serialized = JSON.stringify(log.body);
  assert.equal(serialized.includes(TEST_SECRET), false);
  assert.equal(serialized.includes('"signature":'), false);
  assert.match(serialized, /"signatureHash":"sha256:[0-9a-f]{64}"/);
  assert.equal(serialized.includes('"actingCredential"'), false);
  assert.equal(serialized.includes('"grantorCredential"'), false);
  assert.equal(serialized.includes('"policy":{"'), false);
});
