import assert from "node:assert/strict";
import test from "node:test";
import { createReferenceApp } from "@ordin/zkyc-core-api-reference";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type AccessDecision,
  type CapabilityDelegation,
  type ConsumeStepUpAuthorizationRequest,
  type Credential,
  type FetchLike,
  type OnboardingView,
  type PolicyInput,
  type Principal,
  type ReceiptExpectedBinding,
  type StepUpAuthorization,
} from "../src/index.js";

const JSON_HEADERS = { "content-type": "application/json" };
const START = "2026-06-01T00:10:00.000Z";
const LATER = "2026-06-01T00:11:00.000Z";
const EXPIRY = "2026-06-01T01:00:00.000Z";
const ARTIFACT_EXPIRY = "2026-06-01T00:20:00.000Z";
const RESOURCE = "record:sdk-reference";
const HMAC_KEY = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
const HASH_0 = `sha256:${"0".repeat(64)}`;
const HASH_1 = `sha256:${"1".repeat(64)}`;

function jsonResponse(body: unknown, status = 200, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}

function harness() {
  let now = START;
  const counters = new Map<string, number>();
  const calls: { readonly url: string; readonly init?: RequestInit }[] = [];
  const app = createReferenceApp({
    clock: () => now,
    idFactory: (kind) => {
      const next = (counters.get(kind) ?? 0) + 1;
      counters.set(kind, next);
      return `${kind}:${next}`;
    },
    receiptHmacKey: HMAC_KEY,
    issuerId: "issuer:sdk-reference",
  });
  const fetch: FetchLike = (input, init) => {
    calls.push({ url: String(input), ...(init === undefined ? {} : { init }) });
    return app.request(String(input), init);
  };
  return {
    client: new ZkycReferenceClient({ baseUrl: "https://sdk.reference/", fetch }),
    calls,
    setNow(value: string) {
      now = value;
    },
  };
}

const human: Principal = {
  id: "principal:alice",
  type: "HUMAN",
  affiliations: [],
};

function policy(effect: "ALLOW" | "DENY" | "STEP_UP", action: string): PolicyInput {
  return {
    id: `policy:${effect.toLowerCase()}:${action.replaceAll(":", "-")}`,
    rules: [{
      action,
      actionSensitivity: effect === "STEP_UP" ? "SENSITIVE" : "ROUTINE",
      requiredCapabilities: [action],
      requiredAffiliations: [],
      effect,
      ...(effect === "STEP_UP" ? { approverCapability: "approval:records-export" } : {}),
    }],
  };
}

async function issueCredential(
  client: ZkycReferenceClient,
  principal: Principal,
  capabilities: readonly string[],
  allowedActions = capabilities,
): Promise<Credential> {
  const response = await client.issueCredential({
    principal,
    capabilities,
    allowedActions,
    allowedResourceIds: [RESOURCE],
    expiresAt: EXPIRY,
  });
  return response.credential;
}

function receiptExpected(decision: AccessDecision): ReceiptExpectedBinding {
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
    ...(decision.requiredApproverCapability === undefined
      ? {}
      : { requiredApproverCapability: decision.requiredApproverCapability }),
  };
  if (decision.authorityMode === "DIRECT") {
    if (decision.credentialId === undefined) throw new Error("direct decision omitted compatibility binding");
    return { ...common, authorityMode: "DIRECT", credentialId: decision.credentialId };
  }
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

function authorizationBinding(
  authorization: StepUpAuthorization,
): ConsumeStepUpAuthorizationRequest {
  const common = {
    authorization,
    requestId: authorization.requestId,
    authorityMode: authorization.authorityMode,
    subjectId: authorization.subjectId,
    subjectType: authorization.subjectType,
    actingCredentialId: authorization.actingCredentialId,
    effectiveScopeHash: authorization.effectiveScopeHash,
    action: authorization.action,
    actionSensitivity: authorization.actionSensitivity,
    resourceId: authorization.resourceId,
    contextHash: authorization.contextHash,
    policyId: authorization.policyId,
    policyVersion: authorization.policyVersion,
    requiredApproverCapability: authorization.requiredApproverCapability,
    approvedBy: authorization.approvedBy,
    approvedByType: authorization.approvedByType,
    approverCredentialId: authorization.approverCredentialId,
  };
  if (authorization.authorityMode === "DIRECT") {
    if (authorization.credentialId === undefined) throw new Error("direct authorization omitted compatibility binding");
    return { ...common, authorityMode: "DIRECT", credentialId: authorization.credentialId };
  }
  return {
    ...common,
    authorityMode: "DELEGATED",
    grantorId: authorization.grantorId,
    grantorType: authorization.grantorType,
    grantorCredentialId: authorization.grantorCredentialId,
    delegationId: authorization.delegationId,
    delegationBindingHash: authorization.delegationBindingHash,
  };
}

test("SDK executes the direct v0.3 lifecycle through the real Hono adapter", async () => {
  const { client, calls } = harness();
  assert.deepEqual(await client.health(), {
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.3.0",
    state: "in-memory-reference-only",
  });

  const credential = await issueCredential(client, human, ["records:read"]);
  assert.equal(credential.version, 2);
  assert.equal(credential.principalType, "HUMAN");
  assert.deepEqual(credential.allowedActions, ["records:read"]);
  assert.deepEqual(credential.allowedResourceIds, [RESOURCE]);
  assert.match(credential.scopeHash, /^sha256:[0-9a-f]{64}$/);

  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-direct" },
    policy: policy("ALLOW", "records:read"),
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  });
  assert.equal(evaluated.decision.outcome, "ALLOW");
  assert.equal(evaluated.decision.authorityMode, "DIRECT");
  assert.ok(evaluated.receipt);
  assert.equal(evaluated.receipt.payload.version, 2);

  const initial = await client.getOnboardingView(evaluated.logId);
  assert.equal(initial.verificationStatus, "ACTIVE");
  assert.equal(initial.authorityMode, "DIRECT");
  assert.equal(initial.delegatedScope, null);
  assert.equal(initial.receipt.status, "UNCONSUMED");

  const expected = receiptExpected(evaluated.decision);
  assert.deepEqual(await client.consumeReceipt({ receipt: evaluated.receipt, expected }), {
    valid: true,
    reasonCode: "RECEIPT_VALID",
  });
  assert.deepEqual(await client.consumeReceipt({ receipt: evaluated.receipt, expected }), {
    valid: false,
    reasonCode: "RECEIPT_REPLAYED",
  });
  assert.equal((await client.getOnboardingView(evaluated.logId)).receipt.status, "CONSUMED");

  const log = await client.getDecisionLog();
  assert.equal(log.referenceOnly, true);
  assert.equal(log.entries[0]?.principal.type, "HUMAN");
  assert.equal(log.entries[0]?.receipt?.signatureHash.startsWith("sha256:"), true);

  assert.deepEqual(await client.revokeCredential(credential.id, { reason: "sdk-test" }), { revoked: true });
  const revoked = await client.getOnboardingView(evaluated.logId);
  assert.equal(revoked.verificationStatus, "REVOKED");
  assert.equal(revoked.eligibleActions[0]?.status, "INELIGIBLE");

  assert.deepEqual(calls.map((call) => [call.init?.method ?? "GET", new URL(call.url).pathname]), [
    ["GET", "/health"],
    ["POST", "/credentials"],
    ["POST", "/evaluations"],
    ["GET", `/zkya/onboarding-views/${encodeURIComponent(evaluated.logId)}`],
    ["POST", "/receipts/consume"],
    ["POST", "/receipts/consume"],
    ["GET", `/zkya/onboarding-views/${encodeURIComponent(evaluated.logId)}`],
    ["GET", "/decision-log"],
    ["POST", `/credentials/${encodeURIComponent(credential.id)}/revoke`],
    ["GET", `/zkya/onboarding-views/${encodeURIComponent(evaluated.logId)}`],
  ]);
});

test("SDK executes delegated issuance, evaluation, onboarding, receipt, and revocation", async () => {
  const { client } = harness();
  const grantor: Principal = { id: "organization:grantor", type: "ORGANIZATION", affiliations: [] };
  const delegate: Principal = { id: "agent:delegate", type: "AGENT", affiliations: [] };
  const grantorCredential = await issueCredential(client, grantor, ["records:read"]);
  const delegateCredential = await issueCredential(
    client,
    delegate,
    ["identity:act"],
    ["records:read"],
  );
  const delegatedPolicy = policy("ALLOW", "records:read");
  const issued = await client.issueDelegation({
    grantor,
    grantorCredential,
    delegate,
    policy: delegatedPolicy,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
    expiresAt: ARTIFACT_EXPIRY,
  });
  const delegation: CapabilityDelegation = issued.delegation;
  assert.equal(delegation.version, 1);
  assert.equal(delegation.delegateType, "AGENT");
  assert.equal(delegation.grantorCredentialId, grantorCredential.id);
  assert.match(delegation.delegationBindingHash, /^sha256:[0-9a-f]{64}$/);

  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: delegate,
    delegateIdentityCredential: delegateCredential,
    grantorCredential,
    delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-delegated" },
    policy: delegatedPolicy,
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  });
  assert.equal(evaluated.decision.authorityMode, "DELEGATED");
  assert.equal(evaluated.decision.delegationId, delegation.id);
  assert.ok(evaluated.receipt);
  assert.equal(evaluated.receipt.payload.authorityMode, "DELEGATED");

  const view = await client.getOnboardingView(evaluated.logId);
  assert.equal(view.principal.type, "AGENT");
  assert.equal(view.delegatedScope?.delegationId, delegation.id);
  assert.equal(view.delegatedScope?.status, "ACTIVE");
  assert.deepEqual(await client.consumeReceipt({
    receipt: evaluated.receipt,
    expected: receiptExpected(evaluated.decision),
  }), { valid: true, reasonCode: "RECEIPT_VALID" });

  assert.deepEqual(await client.revokeDelegation(delegation.id, { reason: "sdk-test" }), { revoked: true });
  const revoked = await client.getOnboardingView(evaluated.logId);
  assert.equal(revoked.verificationStatus, "REVOKED");
  assert.equal(revoked.delegatedScope?.status, "REVOKED");
  assert.equal(revoked.eligibleActions[0]?.status, "INELIGIBLE");
});

test("SDK validates and consumes the complete direct step-up authorization binding", async () => {
  const { client, setNow } = harness();
  const subject = await issueCredential(client, human, ["records:export"]);
  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential: subject,
    action: "records:export",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-step-up" },
    policy: policy("STEP_UP", "records:export"),
    issueReceipt: false,
  });
  assert.equal(evaluated.decision.outcome, "STEP_UP");
  const created = await client.createStepUpRequest({
    decisionLogId: evaluated.logId,
    expiresAt: ARTIFACT_EXPIRY,
  });
  assert.equal(created.request.version, 2);
  assert.equal(created.request.authorityMode, "DIRECT");

  const approver: Principal = { id: "principal:approver", type: "HUMAN", affiliations: [] };
  const approverCredential = await issueCredential(
    client,
    approver,
    ["approval:records-export"],
    ["step-up:resolve"],
  );
  setNow(LATER);
  const resolved = await client.resolveStepUpRequest(created.request.id, {
    resolution: "APPROVE",
    approver,
    approverCredential,
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) throw new Error("expected approval authorization");
  assert.equal(resolved.authorization.version, 2);
  assert.equal(resolved.authorization.approvedByType, "HUMAN");

  const binding = authorizationBinding(resolved.authorization);
  assert.deepEqual(await client.consumeStepUpAuthorization(binding), { authorized: true });
  assert.deepEqual(await client.consumeStepUpAuthorization(binding), { authorized: false });
  assert.equal((await client.getOnboardingView(evaluated.logId)).requiredApproval.status, "APPROVED");
});

const staticCredential: Credential = {
  version: 2,
  id: "credential:static",
  issuerId: "issuer:static",
  principalId: human.id,
  principalType: human.type,
  affiliations: [],
  capabilities: ["records:read"],
  allowedActions: ["records:read"],
  allowedResourceIds: [RESOURCE],
  issuedAt: START,
  expiresAt: EXPIRY,
  scopeHash: HASH_0,
};

const staticDecision: AccessDecision = {
  version: 2,
  outcome: "ALLOW",
  reasonCode: "POLICY_ALLOW",
  authorityMode: "DIRECT",
  subjectId: human.id,
  subjectType: human.type,
  actingCredentialId: staticCredential.id,
  effectiveScopeHash: staticCredential.scopeHash,
  action: "records:read",
  actionSensitivity: "ROUTINE",
  resourceId: RESOURCE,
  contextHash: HASH_0,
  policyId: "policy:static",
  policyVersion: HASH_1,
  credentialId: staticCredential.id,
  decidedAt: START,
};

const staticDelegation: CapabilityDelegation = {
  version: 1,
  id: "delegation:static",
  issuerId: "issuer:static",
  grantorCredentialId: staticCredential.id,
  grantorId: human.id,
  grantorType: human.type,
  delegateId: "agent:static",
  delegateType: "AGENT",
  policyId: staticDecision.policyId,
  policyVersion: staticDecision.policyVersion,
  capabilities: ["records:read"],
  allowedActions: ["records:read"],
  allowedResourceIds: [RESOURCE],
  issuedAt: START,
  expiresAt: EXPIRY,
  scopeHash: HASH_0,
  delegationBindingHash: HASH_1,
};

const staticView: OnboardingView = {
  version: 1,
  referenceOnly: true,
  decisionLogId: "decision-log:static",
  verificationStatus: "ACTIVE",
  principal: human,
  authorityMode: "DIRECT",
  delegatedScope: null,
  eligibleActions: [{
    action: "records:read",
    resourceId: RESOURCE,
    status: "ELIGIBLE",
    reasonCode: "POLICY_ALLOW",
  }],
  requiredApproval: { status: "NOT_REQUIRED" },
  receipt: { status: "NOT_ISSUED" },
  policyId: staticDecision.policyId,
  policyVersion: staticDecision.policyVersion,
};

const staticAuthorization: StepUpAuthorization = {
  version: 2,
  id: "step-up-authorization:static",
  requestId: "step-up-request:static",
  authorityMode: "DIRECT",
  subjectId: human.id,
  subjectType: human.type,
  actingCredentialId: staticCredential.id,
  effectiveScopeHash: staticCredential.scopeHash,
  action: "records:export",
  actionSensitivity: "SENSITIVE",
  resourceId: RESOURCE,
  contextHash: HASH_0,
  policyId: "policy:step-up",
  policyVersion: HASH_1,
  credentialId: staticCredential.id,
  requiredApproverCapability: "approval:records-export",
  approvedBy: human.id,
  approvedByType: human.type,
  approverCredentialId: staticCredential.id,
  issuedAt: START,
  expiresAt: ARTIFACT_EXPIRY,
};

async function expectInvalidResponse(action: () => Promise<unknown>): Promise<void> {
  await assert.rejects(
    action,
    (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
  );
}

test("SDK rejects valid responses bound to a different requested authority record", async () => {
  const credentialClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      credential: { ...staticCredential, principalId: "principal:other" },
    }, 201)),
  });
  await expectInvalidResponse(() => credentialClient.issueCredential({
    principal: human,
    capabilities: staticCredential.capabilities,
    allowedActions: staticCredential.allowedActions,
    allowedResourceIds: staticCredential.allowedResourceIds,
    expiresAt: staticCredential.expiresAt,
  }));

  const delegate: Principal = { id: staticDelegation.delegateId, type: "AGENT", affiliations: [] };
  const delegationClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      delegation: { ...staticDelegation, delegateId: "agent:other" },
    }, 201)),
  });
  await expectInvalidResponse(() => delegationClient.issueDelegation({
    grantor: human,
    grantorCredential: staticCredential,
    delegate,
    policy: { id: staticDelegation.policyId, rules: [] },
    capabilities: staticDelegation.capabilities,
    allowedActions: staticDelegation.allowedActions,
    allowedResourceIds: staticDelegation.allowedResourceIds,
    expiresAt: staticDelegation.expiresAt,
  }));

  const evaluationClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:static",
      decision: { ...staticDecision, subjectId: "principal:other" },
    })),
  });
  await expectInvalidResponse(() => evaluationClient.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential: staticCredential,
    action: staticDecision.action,
    resourceId: staticDecision.resourceId,
    actionContext: {},
    policy: { id: staticDecision.policyId, rules: [] },
    issueReceipt: false,
  }));

  const onboardingClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      ...staticView,
      decisionLogId: "decision-log:other",
    })),
  });
  await expectInvalidResponse(() => onboardingClient.getOnboardingView(staticView.decisionLogId));

  const resolutionClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      ok: true,
      authorization: { ...staticAuthorization, requestId: "step-up-request:other" },
    })),
  });
  await expectInvalidResponse(() => resolutionClient.resolveStepUpRequest(staticAuthorization.requestId, {
    resolution: "APPROVE",
    approver: human,
    approverCredential: staticCredential,
  }));
});

test("SDK rejects valid decision-log entries whose duplicated principal identity conflicts", async () => {
  const client = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      referenceOnly: true,
      entries: [{
        id: "decision-log:static",
        recordedAt: START,
        principal: { ...human, id: "principal:other" },
        decision: staticDecision,
      }],
    })),
  });
  await expectInvalidResponse(() => client.getDecisionLog());
});

test("SDK rejects v0.3 successful responses with missing, unknown, or mixed authority bindings", async () => {
  const issueInput = {
    principal: human,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
    expiresAt: EXPIRY,
  } as const;
  const malformedCredentials = [
    { ...staticCredential, version: 1 },
    { ...staticCredential, principalType: undefined },
    { ...staticCredential, scopeHash: undefined },
    { ...staticCredential, allowedActions: ["records:read", "records:read"] },
    { ...staticCredential, unexpected: true },
  ];
  for (const malformed of malformedCredentials) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({ credential: malformed }, 201)),
    });
    await expectInvalidResponse(() => client.issueCredential(issueInput));
  }

  for (const malformedDecision of [
    { ...staticDecision, subjectType: undefined },
    { ...staticDecision, authorityMode: "DELEGATED" },
    { ...staticDecision, grantorId: "organization:injected" },
    { ...staticDecision, requiredApproverCapability: "approval:unexpected" },
    { ...staticDecision, unexpected: true },
  ]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({ logId: "decision-log:bad", decision: malformedDecision })),
    });
    await expectInvalidResponse(() => client.evaluate({
      authorityMode: "DIRECT",
      principal: human,
      credential: staticCredential,
      action: "records:read",
      resourceId: RESOURCE,
      actionContext: {},
      policy: policy("ALLOW", "records:read"),
      issueReceipt: false,
    }));
  }

  const directView: OnboardingView = {
    version: 1,
    referenceOnly: true,
    decisionLogId: "decision-log:static",
    verificationStatus: "ACTIVE",
    principal: human,
    authorityMode: "DIRECT",
    delegatedScope: null,
    eligibleActions: [{
      action: "records:read",
      resourceId: RESOURCE,
      status: "ELIGIBLE",
      reasonCode: "POLICY_ALLOW",
    }],
    requiredApproval: { status: "NOT_REQUIRED" },
    receipt: { status: "NOT_ISSUED" },
    policyId: staticDecision.policyId,
    policyVersion: staticDecision.policyVersion,
  };
  for (const malformedView of [
    { ...directView, delegatedScope: { delegationId: "delegation:injected" } },
    { ...directView, authorityMode: "DELEGATED", delegatedScope: null },
    { ...directView, receipt: { status: "EXPIRED" } },
    { ...directView, requiredApproval: { status: "APPROVED" } },
    { ...directView, eligibleActions: [] },
    { ...directView, unexpected: true },
  ]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse(malformedView)),
    });
    await expectInvalidResponse(() => client.getOnboardingView("decision-log:static"));
  }

  const nonHumanAuthorization = {
    version: 2,
    id: "step-up-authorization:invalid",
    requestId: "step-up-request:invalid",
    authorityMode: "DIRECT",
    subjectId: human.id,
    subjectType: human.type,
    actingCredentialId: staticCredential.id,
    effectiveScopeHash: staticCredential.scopeHash,
    action: "records:export",
    actionSensitivity: "SENSITIVE",
    resourceId: RESOURCE,
    contextHash: HASH_0,
    policyId: "policy:step-up",
    policyVersion: HASH_1,
    credentialId: staticCredential.id,
    requiredApproverCapability: "approval:records-export",
    approvedBy: "agent:invalid-approver",
    approvedByType: "AGENT",
    approverCredentialId: "credential:invalid-approver",
    issuedAt: START,
    expiresAt: ARTIFACT_EXPIRY,
  };
  const authorizationClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({ ok: true, authorization: nonHumanAuthorization })),
  });
  await expectInvalidResponse(() => authorizationClient.resolveStepUpRequest("step-up-request:invalid", {
    resolution: "APPROVE",
    approver: human,
    approverCredential: staticCredential,
  }));

  const missingPrincipalLog = {
    referenceOnly: true,
    entries: [{ id: "decision-log:static", recordedAt: START, decision: staticDecision }],
  };
  const logClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse(missingPrincipalLog)),
  });
  await expectInvalidResponse(() => logClient.getDecisionLog());
});

test("SDK preserves strict JSON media types, error envelopes, network errors, and encoded parameters", async () => {
  const apiClient = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid/api/",
    fetch: () => Promise.resolve(jsonResponse({
      error: { code: "INVALID_REQUEST", message: "request body is invalid" },
    }, 400)),
  });
  await assert.rejects(
    () => apiClient.health(),
    (error: unknown) => error instanceof ZkycApiError && error.status === 400 && error.code === "INVALID_REQUEST",
  );

  for (const contentType of ["text/html", "application/jsonp", "foo/application/json"]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://reference.invalid",
      fetch: () => Promise.resolve(jsonResponse({ ok: true }, 200, contentType)),
    });
    await expectInvalidResponse(() => client.health());
  }

  const malformedError = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: () => Promise.resolve(jsonResponse({ error: { code: 17, message: "bad" } }, 400)),
  });
  await expectInvalidResponse(() => malformedError.health());

  const networkClient = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: () => Promise.reject(new Error("socket detail must not leak")),
  });
  await assert.rejects(
    () => networkClient.health(),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "NETWORK_ERROR",
  );

  const paths: string[] = [];
  const encodedClient = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid/api/",
    fetch: (input) => {
      paths.push(new URL(String(input)).pathname);
      return Promise.resolve(jsonResponse({ revoked: false }));
    },
  });
  assert.deepEqual(await encodedClient.revokeCredential("credential:with/slash", { reason: "test" }), {
    revoked: false,
  });
  assert.deepEqual(await encodedClient.revokeDelegation("delegation:with/slash", { reason: "test" }), {
    revoked: false,
  });
  assert.deepEqual(paths, [
    "/api/credentials/credential%3Awith%2Fslash/revoke",
    "/api/delegations/delegation%3Awith%2Fslash/revoke",
  ]);
});

test("SDK resolves a browser-relative base URL against the current page", async () => {
  const originalLocation = Reflect.getOwnPropertyDescriptor(globalThis, "location");
  Reflect.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL("https://reviewer.invalid/cockpit"),
  });
  try {
    const calls: string[] = [];
    const client = new ZkycReferenceClient({
      baseUrl: "/api/",
      fetch: (input) => {
        calls.push(String(input));
        return Promise.resolve(jsonResponse({
          ok: true,
          service: "zkyc-core-api-reference",
          version: "0.3.0",
          state: "in-memory-reference-only",
        }));
      },
    });
    await client.health();
    assert.equal(calls[0], "https://reviewer.invalid/api/health");
  } finally {
    if (originalLocation === undefined) Reflect.deleteProperty(globalThis, "location");
    else Reflect.defineProperty(globalThis, "location", originalLocation);
  }
});
