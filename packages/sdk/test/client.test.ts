import assert from "node:assert/strict";
import test from "node:test";
import { createReferenceApp } from "@ordin/zkyc-core-api-reference";
import {
  computeDelegationBindingHash,
  computeScopeHash,
  createPolicy,
  sha256Version,
} from "@ordin/zkyc-core-reference";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type AccessDecision,
  type BoundAccessDecision,
  type BoundDirectAccessDecision,
  type CapabilityDelegation,
  type ConsumeStepUpAuthorizationRequest,
  type Credential,
  type FetchLike,
  type IssueDelegationRequest,
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
    trustedPolicies: [
      policy("ALLOW", "records:read"),
      policy("STEP_UP", "records:export"),
    ] as never[],
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

function isBoundDecision(decision: AccessDecision): decision is BoundAccessDecision {
  return decision.actingCredentialId !== undefined && decision.effectiveScopeHash !== undefined;
}

function receiptExpected(decision: AccessDecision): ReceiptExpectedBinding {
  assert.ok(isBoundDecision(decision), "receipt decision must carry authority bindings");
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

test("SDK accepts the real Hono credentialless direct denial without authority bindings", async () => {
  const { client } = harness();
  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential: null,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-credentialless-denial" },
    policy: policy("ALLOW", "records:read"),
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.outcome, "DENY");
  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_MISSING");
  assert.equal(evaluated.decision.authorityMode, "DIRECT");
  assert.equal("actingCredentialId" in evaluated.decision, false);
  assert.equal("effectiveScopeHash" in evaluated.decision, false);
  assert.equal("credentialId" in evaluated.decision, false);
});

test("SDK accepts real Hono direct CREDENTIAL_MALFORMED without trusted bindings", async () => {
  const { client } = harness();
  const credential = await issueCredential(client, human, ["records:read"]);
  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential: { ...credential, scopeHash: HASH_0 },
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-malformed-direct-denial" },
    policy: policy("ALLOW", "records:read"),
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_MALFORMED");
  assert.equal("actingCredentialId" in evaluated.decision, false);
  assert.equal("effectiveScopeHash" in evaluated.decision, false);
  assert.equal("credentialId" in evaluated.decision, false);
});

test("SDK accepts real Hono direct CREDENTIAL_UNKNOWN without trusted bindings", async () => {
  const { client } = harness();
  const credential = await issueCredential(client, human, ["records:read"]);
  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential: { ...credential, id: "credential:unknown-direct" },
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-unknown-direct-denial" },
    policy: policy("ALLOW", "records:read"),
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_UNKNOWN");
  assert.equal("actingCredentialId" in evaluated.decision, false);
  assert.equal("effectiveScopeHash" in evaluated.decision, false);
  assert.equal("credentialId" in evaluated.decision, false);
});

test("SDK preserves real Hono server-authoritative direct CREDENTIAL_REVOKED binding", async () => {
  const { client } = harness();
  const credential = await issueCredential(client, human, ["records:read"]);
  assert.deepEqual(await client.revokeCredential(credential.id, { reason: "direct-evaluation-test" }), {
    revoked: true,
  });

  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal: human,
    credential,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-revoked-direct-denial" },
    policy: policy("ALLOW", "records:read"),
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  });

  assert.equal(evaluated.decision.outcome, "DENY");
  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_REVOKED");
  assert.equal(evaluated.decision.actingCredentialId, credential.id);
  assert.equal(evaluated.decision.effectiveScopeHash, credential.scopeHash);
  assert.equal(evaluated.decision.credentialId, credential.id);
  assert.equal(evaluated.receipt, undefined);
});

async function issueDelegatedFixture(client: ZkycReferenceClient) {
  const grantor: Principal = { id: "organization:fixture-grantor", type: "ORGANIZATION", affiliations: [] };
  const delegate: Principal = { id: "agent:fixture-delegate", type: "AGENT", affiliations: [] };
  const grantorCredential = await issueCredential(client, grantor, ["records:read"]);
  const delegateIdentityCredential = await issueCredential(
    client,
    delegate,
    ["identity:act"],
    ["records:read"],
  );
  const delegatedPolicy = policy("ALLOW", "records:read");
  const { delegation } = await client.issueDelegation({
    grantor,
    grantorCredential,
    delegate,
    policy: delegatedPolicy,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
    expiresAt: ARTIFACT_EXPIRY,
  });
  return { grantor, delegate, grantorCredential, delegateIdentityCredential, delegatedPolicy, delegation };
}

test("SDK accepts real Hono delegated CREDENTIAL_MALFORMED without trusted bindings", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: { ...fixture.delegateIdentityCredential, scopeHash: HASH_0 },
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-malformed-delegate-credential" },
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_MALFORMED");
  assert.equal(evaluated.decision.authorityMode, "DELEGATED");
  assert.equal("actingCredentialId" in evaluated.decision, false);
  assert.equal("effectiveScopeHash" in evaluated.decision, false);
  assert.equal("grantorId" in evaluated.decision, false);
});

test("SDK accepts real Hono delegated CREDENTIAL_UNKNOWN without trusted bindings", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: {
      ...fixture.delegateIdentityCredential,
      id: "credential:unknown-delegate",
    },
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-unknown-delegate-credential" },
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_UNKNOWN");
  assert.equal(evaluated.decision.authorityMode, "DELEGATED");
  assert.equal("actingCredentialId" in evaluated.decision, false);
  assert.equal("effectiveScopeHash" in evaluated.decision, false);
  assert.equal("grantorId" in evaluated.decision, false);
});

test("SDK preserves real Hono server-authoritative revoked delegate credential denial", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  assert.deepEqual(await client.revokeCredential(fixture.delegateIdentityCredential.id, {
    reason: "delegated-evaluation-test",
  }), { revoked: true });

  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-revoked-delegate-credential" },
    policy: fixture.delegatedPolicy,
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  });

  assert.equal(evaluated.decision.outcome, "DENY");
  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_REVOKED");
  assert.equal(evaluated.decision.actingCredentialId, fixture.delegateIdentityCredential.id);
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegateIdentityCredential.scopeHash);
  assert.equal("grantorId" in evaluated.decision, false);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK accepts real Hono delegated acting-only DELEGATION_MALFORMED", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.grantorCredential,
    delegation: { ...fixture.delegation, scopeHash: HASH_0 },
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-malformed-delegation" },
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "DELEGATION_MALFORMED");
  assert.equal(evaluated.decision.actingCredentialId, fixture.delegateIdentityCredential.id);
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegateIdentityCredential.scopeHash);
  assert.equal("grantorId" in evaluated.decision, false);
  assert.equal("delegationId" in evaluated.decision, false);
});

test("SDK accepts real Hono delegated acting-only DELEGATION_IDENTITIES_NOT_DISTINCT", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.delegateIdentityCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-identities-not-distinct" },
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "DELEGATION_IDENTITIES_NOT_DISTINCT");
  assert.equal(evaluated.decision.actingCredentialId, fixture.delegateIdentityCredential.id);
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegateIdentityCredential.scopeHash);
  assert.equal("grantorId" in evaluated.decision, false);
  assert.equal("delegationId" in evaluated.decision, false);
});

test("SDK preserves issuance DELEGATION_IDENTITIES_NOT_DISTINCT as an HTTP domain error", async () => {
  const { client } = harness();
  const principal: Principal = { id: "organization:same-party", type: "ORGANIZATION", affiliations: [] };
  const grantorCredential = await issueCredential(client, principal, ["records:read"]);

  await assert.rejects(
    () => client.issueDelegation({
      grantor: principal,
      grantorCredential,
      delegate: principal,
      policy: policy("ALLOW", "records:read"),
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: ARTIFACT_EXPIRY,
    }),
    (error: unknown) =>
      error instanceof ZkycApiError &&
      error.status === 400 &&
      error.code === "DELEGATION_IDENTITIES_NOT_DISTINCT",
  );
});

test("SDK accepts real Hono fully bound DELEGATION_POLICY_MISMATCH", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:export",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-delegation-policy-mismatch" },
    policy: policy("STEP_UP", "records:export"),
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "DELEGATION_POLICY_MISMATCH");
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegation.scopeHash);
  assert.equal(evaluated.decision.grantorId, fixture.delegation.grantorId);
  assert.equal(evaluated.decision.delegationId, fixture.delegation.id);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK accepts real Hono fully bound revoked delegation denial", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  assert.deepEqual(await client.revokeDelegation(fixture.delegation.id, {
    reason: "delegated-evaluation-test",
  }), { revoked: true });

  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-revoked-delegation" },
    policy: fixture.delegatedPolicy,
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  });

  assert.equal(evaluated.decision.outcome, "DENY");
  assert.equal(evaluated.decision.reasonCode, "DELEGATION_REVOKED");
  assert.equal(evaluated.decision.actingCredentialId, fixture.delegateIdentityCredential.id);
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegation.scopeHash);
  assert.equal(evaluated.decision.grantorId, fixture.delegation.grantorId);
  assert.equal(evaluated.decision.grantorType, fixture.delegation.grantorType);
  assert.equal(evaluated.decision.grantorCredentialId, fixture.delegation.grantorCredentialId);
  assert.equal(evaluated.decision.delegationId, fixture.delegation.id);
  assert.equal(evaluated.decision.delegationBindingHash, fixture.delegation.delegationBindingHash);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK accepts real Hono fully bound malformed grantor credential denial", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const evaluated = await client.evaluate({
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: {} as Credential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: { purpose: "sdk-malformed-grantor-credential" },
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  });

  assert.equal(evaluated.decision.reasonCode, "DELEGATION_GRANTOR_CREDENTIAL_INVALID");
  assert.equal(evaluated.decision.effectiveScopeHash, fixture.delegation.scopeHash);
  assert.equal(evaluated.decision.grantorCredentialId, fixture.delegation.grantorCredentialId);
  assert.equal(evaluated.decision.delegationId, fixture.delegation.id);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK rejects prohibited and mixed delegated denial bindings", async () => {
  const { client } = harness();
  const fixture = await issueDelegatedFixture(client);
  const delegatedPolicy = createPolicy(fixture.delegatedPolicy);
  const input = {
    authorityMode: "DELEGATED",
    principal: fixture.delegate,
    delegateIdentityCredential: fixture.delegateIdentityCredential,
    grantorCredential: fixture.grantorCredential,
    delegation: fixture.delegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: {},
    policy: fixture.delegatedPolicy,
    issueReceipt: false,
  } as const;
  const unbound = {
    version: 2,
    outcome: "DENY",
    reasonCode: "CREDENTIAL_UNKNOWN",
    authorityMode: "DELEGATED",
    subjectId: fixture.delegate.id,
    subjectType: fixture.delegate.type,
    action: "records:read",
    actionSensitivity: "ROUTINE",
    resourceId: RESOURCE,
    contextHash: emptyContextHash,
    policyId: delegatedPolicy.id,
    policyVersion: delegatedPolicy.version,
    decidedAt: START,
  } as const;
  const actingOnly = {
    ...unbound,
    reasonCode: "DELEGATION_MALFORMED",
    actingCredentialId: fixture.delegateIdentityCredential.id,
    effectiveScopeHash: fixture.delegateIdentityCredential.scopeHash,
  } as const;
  const fullyBound = {
    ...actingOnly,
    grantorId: fixture.delegation.grantorId,
    grantorType: fixture.delegation.grantorType,
    grantorCredentialId: fixture.delegation.grantorCredentialId,
    delegationId: fixture.delegation.id,
    delegationBindingHash: fixture.delegation.delegationBindingHash,
  } as const;

  for (const decision of [
    { ...unbound, reasonCode: "POLICY_DENY" },
    { ...unbound, unverifiedMetadata: {} },
    { ...unbound, actingCredentialId: fixture.delegateIdentityCredential.id },
    { ...unbound, effectiveScopeHash: fixture.delegateIdentityCredential.scopeHash },
    { ...actingOnly, credentialId: fixture.delegateIdentityCredential.id },
    { ...actingOnly, grantorId: fixture.delegation.grantorId },
    { ...actingOnly, reasonCode: "DELEGATION_GRANTOR_CREDENTIAL_INVALID" },
    {
      ...actingOnly,
      reasonCode: "CREDENTIAL_REVOKED",
      unverifiedMetadata: { zkPassProofId: "proof:must-not-be-echoed" },
    },
    { ...fullyBound, reasonCode: "CREDENTIAL_UNKNOWN" },
    { ...fullyBound, reasonCode: "DELEGATION_MALFORMED" },
    { ...fullyBound, reasonCode: "DELEGATION_UNKNOWN" },
  ]) {
    const forgedClient = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({ logId: "decision-log:mixed-denial", decision })),
    });
    await expectInvalidResponse(() => forgedClient.evaluate(input));
  }
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
  await assert.rejects(
    () => client.issueDelegation({
      grantor: {
        ...grantor,
        affiliations: [{ organizationId: "organization:forged", role: "admin" }],
      },
      grantorCredential,
      delegate,
      policy: delegatedPolicy,
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: ARTIFACT_EXPIRY,
    }),
    (error: unknown) =>
      error instanceof ZkycApiError &&
      error.status === 400 &&
      error.code === "DELEGATION_GRANTOR_MISMATCH",
  );
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

const staticPolicyInput: PolicyInput = {
  id: "policy:static",
  rules: [{
    action: "records:read",
    actionSensitivity: "ROUTINE",
    requiredCapabilities: ["records:read"],
    requiredAffiliations: [],
    effect: "ALLOW",
  }],
};
const staticPolicy = createPolicy(staticPolicyInput);
const staticScopeHash = computeScopeHash({
  capabilities: ["records:read"],
  allowedActions: ["records:read"],
  allowedResourceIds: [RESOURCE],
});
const emptyContextHash = sha256Version({});

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
  scopeHash: staticScopeHash,
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
  contextHash: emptyContextHash,
  policyId: staticPolicy.id,
  policyVersion: staticPolicy.version,
  credentialId: staticCredential.id,
  decidedAt: START,
};

// @ts-expect-error Inactive direct credential denials never carry unverified metadata.
const invalidInactiveDirectMetadataDecision: BoundDirectAccessDecision = {
  ...staticDecision,
  outcome: "DENY",
  reasonCode: "CREDENTIAL_REVOKED",
  unverifiedMetadata: { zkPassProofId: "proof:must-not-be-typed" },
};
void invalidInactiveDirectMetadataDecision;

const staticStepUpRequest = {
  version: 2,
  id: "step-up-request:static",
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
  requestedAt: START,
  expiresAt: ARTIFACT_EXPIRY,
  status: "PENDING",
} as const;

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

const staticDirectDenyDecision = {
  version: 2,
  outcome: "DENY",
  authorityMode: "DIRECT",
  subjectId: human.id,
  subjectType: human.type,
  action: staticDecision.action,
  actionSensitivity: staticDecision.actionSensitivity,
  resourceId: staticDecision.resourceId,
  contextHash: staticDecision.contextHash,
  policyId: staticDecision.policyId,
  policyVersion: staticDecision.policyVersion,
  decidedAt: staticDecision.decidedAt,
} as const;

const staticBoundDirectDenyDecision = {
  ...staticDirectDenyDecision,
  actingCredentialId: staticCredential.id,
  effectiveScopeHash: staticCredential.scopeHash,
  credentialId: staticCredential.id,
} as const;

const staticDirectEvaluationInput = {
  authorityMode: "DIRECT",
  principal: human,
  credential: staticCredential,
  action: staticDecision.action,
  resourceId: staticDecision.resourceId,
  actionContext: {},
  policy: staticPolicyInput,
  issueReceipt: false,
} as const;

test("SDK rejects direct denial reasons contradicted by request-observable authority", async (t) => {
  const contradictions = [
    { reasonCode: "CREDENTIAL_MALFORMED", binding: "UNBOUND" },
    { reasonCode: "CREDENTIAL_NOT_YET_VALID", binding: "BOUND" },
    { reasonCode: "CREDENTIAL_EXPIRED", binding: "BOUND" },
    { reasonCode: "CREDENTIAL_SUBJECT_MISMATCH", binding: "BOUND" },
    { reasonCode: "ACTION_OUTSIDE_CREDENTIAL_SCOPE", binding: "BOUND" },
    { reasonCode: "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE", binding: "BOUND" },
    { reasonCode: "INSUFFICIENT_CAPABILITY", binding: "BOUND" },
    { reasonCode: "AFFILIATION_REQUIRED", binding: "BOUND" },
  ] as const;

  for (const contradiction of contradictions) {
    await t.test(contradiction.reasonCode, async () => {
      const decision = {
        ...(contradiction.binding === "BOUND"
          ? staticBoundDirectDenyDecision
          : staticDirectDenyDecision),
        reasonCode: contradiction.reasonCode,
      };
      const client = new ZkycReferenceClient({
        baseUrl: "https://invalid.reference",
        fetch: () => Promise.resolve(jsonResponse({
          logId: `decision-log:contradicted-${contradiction.reasonCode.toLowerCase()}`,
          decision,
        })),
      });

      await expectInvalidResponse(() => client.evaluate(staticDirectEvaluationInput));
    });
  }
});

test("SDK preserves server-authoritative direct unknown and revoked denials", async (t) => {
  const controls = [
    {
      reasonCode: "CREDENTIAL_UNKNOWN",
      decision: { ...staticDirectDenyDecision, reasonCode: "CREDENTIAL_UNKNOWN" },
    },
    {
      reasonCode: "CREDENTIAL_REVOKED",
      decision: { ...staticBoundDirectDenyDecision, reasonCode: "CREDENTIAL_REVOKED" },
    },
  ] as const;

  for (const control of controls) {
    await t.test(control.reasonCode, async () => {
      const client = new ZkycReferenceClient({
        baseUrl: "https://valid.reference",
        fetch: () => Promise.resolve(jsonResponse({
          logId: `decision-log:server-authoritative-${control.reasonCode.toLowerCase()}`,
          decision: control.decision,
        })),
      });

      const evaluated = await client.evaluate(staticDirectEvaluationInput);
      assert.equal(evaluated.decision.outcome, "DENY");
      assert.equal(evaluated.decision.reasonCode, control.reasonCode);
      if (control.reasonCode === "CREDENTIAL_UNKNOWN") {
        assert.equal("actingCredentialId" in evaluated.decision, false);
        assert.equal("effectiveScopeHash" in evaluated.decision, false);
        assert.equal("credentialId" in evaluated.decision, false);
      } else {
        assert.equal(evaluated.decision.actingCredentialId, staticCredential.id);
        assert.equal(evaluated.decision.effectiveScopeHash, staticCredential.scopeHash);
        assert.equal(evaluated.decision.credentialId, staticCredential.id);
      }
      assert.equal(evaluated.receipt, undefined);
    });
  }
});

const delegatedCorrelationPrincipal: Principal = {
  id: "agent:delegated-correlation",
  type: "AGENT",
  affiliations: [],
};
const delegatedCredentialScope = {
  capabilities: ["identity:act"],
  allowedActions: ["records:read"],
  allowedResourceIds: [RESOURCE],
} as const;
const delegatedCorrelationCredential: Credential = {
  version: 2,
  id: "credential:delegated-correlation",
  issuerId: staticCredential.issuerId,
  principalId: delegatedCorrelationPrincipal.id,
  principalType: delegatedCorrelationPrincipal.type,
  affiliations: [],
  ...delegatedCredentialScope,
  issuedAt: START,
  expiresAt: EXPIRY,
  scopeHash: computeScopeHash(delegatedCredentialScope),
};
const delegatedCorrelationScope = {
  capabilities: ["records:read"],
  allowedActions: ["records:read"],
  allowedResourceIds: [RESOURCE],
} as const;
const delegatedCorrelationSeed: CapabilityDelegation = {
  version: 1,
  id: "delegation:correlation",
  issuerId: staticCredential.issuerId,
  grantorCredentialId: staticCredential.id,
  grantorId: staticCredential.principalId,
  grantorType: staticCredential.principalType,
  delegateId: delegatedCorrelationPrincipal.id,
  delegateType: delegatedCorrelationPrincipal.type,
  policyId: staticPolicy.id,
  policyVersion: staticPolicy.version,
  ...delegatedCorrelationScope,
  issuedAt: START,
  expiresAt: EXPIRY,
  scopeHash: computeScopeHash(delegatedCorrelationScope),
  delegationBindingHash: HASH_0,
};
const delegatedCorrelationDelegation: CapabilityDelegation = {
  ...delegatedCorrelationSeed,
  delegationBindingHash: computeDelegationBindingHash(delegatedCorrelationSeed as never),
};
const delegatedCorrelationInput = {
  authorityMode: "DELEGATED",
  principal: delegatedCorrelationPrincipal,
  delegateIdentityCredential: delegatedCorrelationCredential,
  grantorCredential: staticCredential,
  delegation: delegatedCorrelationDelegation,
  action: staticDecision.action,
  resourceId: staticDecision.resourceId,
  actionContext: {},
  policy: staticPolicyInput,
  issueReceipt: false,
} as const;
const delegatedUnboundDenyDecision = {
  ...staticDirectDenyDecision,
  authorityMode: "DELEGATED",
  subjectId: delegatedCorrelationPrincipal.id,
  subjectType: delegatedCorrelationPrincipal.type,
} as const;
const delegatedActingOnlyDenyDecision = {
  ...delegatedUnboundDenyDecision,
  actingCredentialId: delegatedCorrelationCredential.id,
  effectiveScopeHash: delegatedCorrelationCredential.scopeHash,
} as const;

function correlatedDelegation(
  overrides: Partial<CapabilityDelegation> = {},
): CapabilityDelegation {
  const altered = { ...delegatedCorrelationDelegation, ...overrides };
  const scopeHash = computeScopeHash({
    capabilities: altered.capabilities,
    allowedActions: altered.allowedActions,
    allowedResourceIds: altered.allowedResourceIds,
  });
  const rebound = { ...altered, scopeHash };
  return {
    ...rebound,
    delegationBindingHash: computeDelegationBindingHash(rebound as never),
  };
}

function fullyBoundDelegatedDenial(
  reasonCode: string,
  delegation: CapabilityDelegation = delegatedCorrelationDelegation,
  credential: Credential = delegatedCorrelationCredential,
) {
  return {
    ...delegatedActingOnlyDenyDecision,
    reasonCode,
    actingCredentialId: credential.id,
    effectiveScopeHash: delegation.scopeHash,
    grantorId: delegation.grantorId,
    grantorType: delegation.grantorType,
    grantorCredentialId: delegation.grantorCredentialId,
    delegationId: delegation.id,
    delegationBindingHash: delegation.delegationBindingHash,
    ...(credential.unverifiedMetadata === undefined
      ? {}
      : { unverifiedMetadata: credential.unverifiedMetadata }),
  };
}

function delegatedDenialClient(decision: unknown): ZkycReferenceClient {
  return new ZkycReferenceClient({
    baseUrl: "https://delegated-denial-correlation.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:delegated-denial-correlation",
      decision,
    })),
  });
}

test("SDK correlates delegated acting-stage unbound credential denials", async (t) => {
  const malformedCredentials: readonly Credential[] = [
    { ...delegatedCorrelationCredential, scopeHash: HASH_0 },
    { ...delegatedCorrelationCredential, capabilities: null } as unknown as Credential,
  ];

  await t.test("rejects impossible CREDENTIAL_MISSING for a typed supplied credential", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedUnboundDenyDecision,
      reasonCode: "CREDENTIAL_MISSING",
    }).evaluate(delegatedCorrelationInput));
  });

  await t.test("rejects CREDENTIAL_MALFORMED for a structurally and integrity-valid credential", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedUnboundDenyDecision,
      reasonCode: "CREDENTIAL_MALFORMED",
    }).evaluate(delegatedCorrelationInput));
  });

  for (const [index, credential] of malformedCredentials.entries()) {
    await t.test(`accepts CREDENTIAL_MALFORMED for malformed credential ${index + 1}`, async () => {
      const evaluated = await delegatedDenialClient({
        ...delegatedUnboundDenyDecision,
        reasonCode: "CREDENTIAL_MALFORMED",
      }).evaluate({ ...delegatedCorrelationInput, delegateIdentityCredential: credential });
      assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_MALFORMED");
      assert.equal(evaluated.receipt, undefined);
    });
  }

  await t.test("accepts server-authoritative CREDENTIAL_UNKNOWN for a valid credential", async () => {
    const evaluated = await delegatedDenialClient({
      ...delegatedUnboundDenyDecision,
      reasonCode: "CREDENTIAL_UNKNOWN",
    }).evaluate(delegatedCorrelationInput);
    assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_UNKNOWN");
    assert.equal(evaluated.receipt, undefined);
  });

  await t.test("rejects CREDENTIAL_UNKNOWN for a malformed credential", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedUnboundDenyDecision,
      reasonCode: "CREDENTIAL_UNKNOWN",
    }).evaluate({
      ...delegatedCorrelationInput,
      delegateIdentityCredential: malformedCredentials[0]!,
    }));
  });
});

test("SDK correlates delegated acting-stage delegate credential inactivity denials", async (t) => {
  const notYetValid = { ...delegatedCorrelationCredential, issuedAt: LATER };
  const expired = {
    ...delegatedCorrelationCredential,
    issuedAt: "2026-05-31T23:00:00.000Z",
    expiresAt: START,
  };
  const cases = [
    { reasonCode: "CREDENTIAL_NOT_YET_VALID", credential: notYetValid },
    { reasonCode: "CREDENTIAL_EXPIRED", credential: expired },
    { reasonCode: "CREDENTIAL_REVOKED", credential: delegatedCorrelationCredential },
  ] as const;

  for (const control of cases) {
    await t.test(`accepts ${control.reasonCode} only at its reachable time state`, async () => {
      const decision = {
        ...delegatedActingOnlyDenyDecision,
        reasonCode: control.reasonCode,
        actingCredentialId: control.credential.id,
        effectiveScopeHash: control.credential.scopeHash,
      };
      const evaluated = await delegatedDenialClient(decision).evaluate({
        ...delegatedCorrelationInput,
        delegateIdentityCredential: control.credential,
      });
      assert.equal(evaluated.decision.reasonCode, control.reasonCode);
      assert.equal(evaluated.receipt, undefined);
    });
  }

  for (const reasonCode of ["CREDENTIAL_NOT_YET_VALID", "CREDENTIAL_EXPIRED"] as const) {
    await t.test(`rejects false ${reasonCode} against an active credential`, async () => {
      await expectInvalidResponse(() => delegatedDenialClient({
        ...delegatedActingOnlyDenyDecision,
        reasonCode,
      }).evaluate(delegatedCorrelationInput));
    });
  }

  for (const credential of [notYetValid, expired]) {
    await t.test(`rejects CREDENTIAL_REVOKED before ${credential === notYetValid ? "issuance" : "expiry"}`, async () => {
      await expectInvalidResponse(() => delegatedDenialClient({
        ...delegatedActingOnlyDenyDecision,
        reasonCode: "CREDENTIAL_REVOKED",
      }).evaluate({ ...delegatedCorrelationInput, delegateIdentityCredential: credential }));
    });
  }
});

test("SDK correlates delegated acting-stage delegation denials", async (t) => {
  await t.test("accepts identities-not-distinct only for equal delegate and grantor credential IDs", async () => {
    const decision = {
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_IDENTITIES_NOT_DISTINCT",
    } as const;
    assert.equal(
      (await delegatedDenialClient(decision).evaluate({
        ...delegatedCorrelationInput,
        grantorCredential: delegatedCorrelationCredential,
      })).decision.reasonCode,
      decision.reasonCode,
    );
    await expectInvalidResponse(() => delegatedDenialClient(decision).evaluate(delegatedCorrelationInput));
  });

  await t.test("rejects identities-not-distinct when grantor credential is an array with a forged ID", async () => {
    const forgedArrayCredential = Object.assign([], {
      id: delegatedCorrelationCredential.id,
    }) as unknown as Credential;
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_IDENTITIES_NOT_DISTINCT",
    }).evaluate({
      ...delegatedCorrelationInput,
      grantorCredential: forgedArrayCredential,
    }));
  });

  const mismatchedCredentials: readonly Credential[] = [
    { ...delegatedCorrelationCredential, principalId: "agent:other" },
    { ...delegatedCorrelationCredential, principalType: "ORGANIZATION" },
    {
      ...delegatedCorrelationCredential,
      affiliations: [{ organizationId: "organization:other", role: "member" }],
    },
  ];
  for (const [index, credential] of mismatchedCredentials.entries()) {
    await t.test(`accepts delegate mismatch for principal contradiction ${index + 1}`, async () => {
      const decision = {
        ...delegatedActingOnlyDenyDecision,
        reasonCode: "DELEGATION_DELEGATE_MISMATCH",
        actingCredentialId: credential.id,
        effectiveScopeHash: credential.scopeHash,
      } as const;
      assert.equal(
        (await delegatedDenialClient(decision).evaluate({
          ...delegatedCorrelationInput,
          delegateIdentityCredential: credential,
        })).decision.reasonCode,
        decision.reasonCode,
      );
    });
  }
  await t.test("rejects delegate mismatch when requested principal matches", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_DELEGATE_MISMATCH",
    }).evaluate(delegatedCorrelationInput));
  });

  const malformedDelegations: readonly CapabilityDelegation[] = [
    { ...delegatedCorrelationDelegation, scopeHash: HASH_0 },
    { ...delegatedCorrelationDelegation, delegationBindingHash: HASH_0 },
    { ...delegatedCorrelationDelegation, capabilities: null } as unknown as CapabilityDelegation,
  ];
  for (const [index, delegation] of malformedDelegations.entries()) {
    await t.test(`accepts DELEGATION_MALFORMED for malformed delegation ${index + 1}`, async () => {
      const evaluated = await delegatedDenialClient({
        ...delegatedActingOnlyDenyDecision,
        reasonCode: "DELEGATION_MALFORMED",
      }).evaluate({ ...delegatedCorrelationInput, delegation });
      assert.equal(evaluated.decision.reasonCode, "DELEGATION_MALFORMED");
      assert.equal(evaluated.receipt, undefined);
    });
  }
  await t.test("rejects DELEGATION_MALFORMED for a valid delegation", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_MALFORMED",
    }).evaluate(delegatedCorrelationInput));
  });

  await t.test("accepts server-authoritative DELEGATION_UNKNOWN for a valid delegation", async () => {
    const evaluated = await delegatedDenialClient({
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_UNKNOWN",
    }).evaluate(delegatedCorrelationInput);
    assert.equal(evaluated.decision.reasonCode, "DELEGATION_UNKNOWN");
    assert.equal(evaluated.receipt, undefined);
  });
  await t.test("rejects DELEGATION_UNKNOWN for a malformed delegation", async () => {
    await expectInvalidResponse(() => delegatedDenialClient({
      ...delegatedActingOnlyDenyDecision,
      reasonCode: "DELEGATION_UNKNOWN",
    }).evaluate({ ...delegatedCorrelationInput, delegation: malformedDelegations[0]! }));
  });
});

test("SDK correlates fully bound delegated status and identity denials in core order", async (t) => {
  const policyMismatchDelegation = correlatedDelegation({
    policyId: "policy:other",
    policyVersion: HASH_1,
  });
  const notYetValidDelegation = correlatedDelegation({ issuedAt: LATER });
  const expiredDelegation = correlatedDelegation({
    issuedAt: "2026-05-31T23:00:00.000Z",
    expiresAt: START,
  });
  const delegateMismatchDelegation = correlatedDelegation({ delegateId: "agent:other" });
  const malformedGrantorCredential = {} as Credential;
  const acceptedStages = [
    {
      reasonCode: "DELEGATION_POLICY_MISMATCH",
      delegation: policyMismatchDelegation,
      grantorCredential: staticCredential,
    },
    {
      reasonCode: "DELEGATION_NOT_YET_VALID",
      delegation: notYetValidDelegation,
      grantorCredential: staticCredential,
    },
    {
      reasonCode: "DELEGATION_EXPIRED",
      delegation: expiredDelegation,
      grantorCredential: staticCredential,
    },
    {
      reasonCode: "DELEGATION_REVOKED",
      delegation: delegatedCorrelationDelegation,
      grantorCredential: staticCredential,
    },
    {
      reasonCode: "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      delegation: delegatedCorrelationDelegation,
      grantorCredential: malformedGrantorCredential,
    },
    {
      reasonCode: "DELEGATION_DELEGATE_MISMATCH",
      delegation: delegateMismatchDelegation,
      grantorCredential: staticCredential,
    },
  ] as const;

  for (const stage of acceptedStages) {
    const decision = fullyBoundDelegatedDenial(stage.reasonCode, stage.delegation);
    const input = {
      ...delegatedCorrelationInput,
      delegation: stage.delegation,
      grantorCredential: stage.grantorCredential,
    };
    await t.test(`accepts reachable ${stage.reasonCode} without a receipt`, async () => {
      const evaluated = await delegatedDenialClient(decision).evaluate(input);
      assert.equal(evaluated.decision.reasonCode, stage.reasonCode);
      assert.equal(evaluated.receipt, undefined);
    });

    const bindingContradictions = [
      { name: "acting credential ID", override: { actingCredentialId: "credential:forged" } },
      { name: "effective delegation scope hash", override: { effectiveScopeHash: HASH_1 } },
      { name: "grantor ID", override: { grantorId: "principal:forged" } },
      { name: "grantor type", override: { grantorType: "ORGANIZATION" } },
      { name: "grantor credential ID", override: { grantorCredentialId: "credential:forged" } },
      { name: "delegation ID", override: { delegationId: "delegation:forged" } },
      { name: "delegation binding hash", override: { delegationBindingHash: HASH_1 } },
      {
        name: "unverified metadata",
        override: { unverifiedMetadata: { zkPassProofId: "proof:forged" } },
      },
    ] as const;
    for (const contradiction of bindingContradictions) {
      await t.test(`${stage.reasonCode} rejects forged ${contradiction.name}`, async () => {
        await expectInvalidResponse(() => delegatedDenialClient({
          ...decision,
          ...contradiction.override,
        }).evaluate(input));
      });
    }
  }

  await t.test("rejects every later status reason when canonical policy mismatches first", async () => {
    for (const reasonCode of [
      "DELEGATION_NOT_YET_VALID",
      "DELEGATION_EXPIRED",
      "DELEGATION_REVOKED",
      "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      "DELEGATION_DELEGATE_MISMATCH",
      "DELEGATION_IDENTITIES_NOT_DISTINCT",
    ] as const) {
      await expectInvalidResponse(() => delegatedDenialClient(
        fullyBoundDelegatedDenial(reasonCode, policyMismatchDelegation),
      ).evaluate({ ...delegatedCorrelationInput, delegation: policyMismatchDelegation }));
    }
  });

  await t.test("rejects policy mismatch when the validated delegation matches canonical policy", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_POLICY_MISMATCH"),
    ).evaluate(delegatedCorrelationInput));
  });

  await t.test("rejects inactive time reasons at the wrong boundary", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_NOT_YET_VALID"),
    ).evaluate(delegatedCorrelationInput));
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_EXPIRED"),
    ).evaluate(delegatedCorrelationInput));
  });

  for (const inactiveDelegation of [notYetValidDelegation, expiredDelegation]) {
    await t.test(`rejects later reasons while delegation is ${
      inactiveDelegation === notYetValidDelegation ? "not yet valid" : "expired"
    }`, async () => {
      for (const reasonCode of [
        "DELEGATION_REVOKED",
        "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
        "DELEGATION_DELEGATE_MISMATCH",
        "DELEGATION_IDENTITIES_NOT_DISTINCT",
      ] as const) {
        await expectInvalidResponse(() => delegatedDenialClient(
          fullyBoundDelegatedDenial(reasonCode, inactiveDelegation),
        ).evaluate({ ...delegatedCorrelationInput, delegation: inactiveDelegation }));
      }
    });
  }

  await t.test("rejects unknown and malformed delegation reasons with forged full bindings", async () => {
    for (const reasonCode of ["DELEGATION_MALFORMED", "DELEGATION_UNKNOWN"] as const) {
      await expectInvalidResponse(() => delegatedDenialClient(
        fullyBoundDelegatedDenial(reasonCode),
      ).evaluate(delegatedCorrelationInput));
    }
  });

  await t.test("rejects defensive fully bound identities-not-distinct for a valid delegation", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_IDENTITIES_NOT_DISTINCT"),
    ).evaluate(delegatedCorrelationInput));
  });

  await t.test("rejects fully bound delegate mismatch when delegation identities match", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_DELEGATE_MISMATCH"),
    ).evaluate(delegatedCorrelationInput));
  });

  await t.test("rejects later full-bound reasons when delegate mismatch must occur first", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_GRANTOR_MISMATCH", delegateMismatchDelegation),
    ).evaluate({
      ...delegatedCorrelationInput,
      delegation: delegateMismatchDelegation,
    }));
  });

  await t.test("accepts schema-valid delegate type contradiction with full binding shape", async () => {
    const typeMismatchDelegation = correlatedDelegation({ delegateType: "ORGANIZATION" });
    const evaluated = await delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_DELEGATE_MISMATCH", typeMismatchDelegation),
    ).evaluate({ ...delegatedCorrelationInput, delegation: typeMismatchDelegation });
    assert.equal(evaluated.decision.reasonCode, "DELEGATION_DELEGATE_MISMATCH");
    assert.equal(evaluated.decision.delegationId, typeMismatchDelegation.id);
    assert.equal(evaluated.receipt, undefined);
  });

  const earlierCredentialContradictions: readonly {
    readonly name: string;
    readonly credential: Credential;
    readonly grantorCredential?: Credential;
  }[] = [
    {
      name: "malformed delegate credential",
      credential: { ...delegatedCorrelationCredential, scopeHash: HASH_0 },
    },
    {
      name: "not-yet-valid delegate credential",
      credential: { ...delegatedCorrelationCredential, issuedAt: LATER },
    },
    {
      name: "expired delegate credential",
      credential: { ...delegatedCorrelationCredential, expiresAt: START },
    },
    {
      name: "delegate principal ID contradiction",
      credential: { ...delegatedCorrelationCredential, principalId: "agent:other" },
    },
    {
      name: "delegate principal type contradiction",
      credential: { ...delegatedCorrelationCredential, principalType: "ORGANIZATION" },
    },
    {
      name: "delegate canonical affiliation contradiction",
      credential: {
        ...delegatedCorrelationCredential,
        affiliations: [{ organizationId: "organization:other", role: "member" }],
      },
    },
    {
      name: "equal supplied grantor credential ID",
      credential: delegatedCorrelationCredential,
      grantorCredential: delegatedCorrelationCredential,
    },
  ];
  for (const contradiction of earlierCredentialContradictions) {
    await t.test(`rejects full binding after ${contradiction.name}`, async () => {
      await expectInvalidResponse(() => delegatedDenialClient(fullyBoundDelegatedDenial(
        "DELEGATION_REVOKED",
        delegatedCorrelationDelegation,
        contradiction.credential,
      )).evaluate({
        ...delegatedCorrelationInput,
        delegateIdentityCredential: contradiction.credential,
        grantorCredential: contradiction.grantorCredential ?? staticCredential,
      }));
    });
  }

  await t.test("rejects full binding for malformed delegation integrity", async () => {
    const malformedDelegation = {
      ...delegatedCorrelationDelegation,
      delegationBindingHash: HASH_0,
    };
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_REVOKED", malformedDelegation),
    ).evaluate({ ...delegatedCorrelationInput, delegation: malformedDelegation }));
  });
});

function correlatedGrantorCredential(overrides: Partial<Credential> = {}): Credential {
  const altered = { ...staticCredential, ...overrides };
  return {
    ...altered,
    scopeHash: computeScopeHash({
      capabilities: altered.capabilities,
      allowedActions: altered.allowedActions,
      allowedResourceIds: altered.allowedResourceIds,
    }),
  };
}

function fullyBoundDelegatedSuccess(
  outcome: "ALLOW" | "STEP_UP",
  delegation: CapabilityDelegation = delegatedCorrelationDelegation,
) {
  const stepUp = outcome === "STEP_UP";
  return {
    ...fullyBoundDelegatedDenial(stepUp ? "HUMAN_APPROVAL_REQUIRED" : "POLICY_ALLOW", delegation),
    outcome,
    reasonCode: stepUp ? "HUMAN_APPROVAL_REQUIRED" : "POLICY_ALLOW",
    actionSensitivity: stepUp ? "SENSITIVE" : "ROUTINE",
    policyId: delegation.policyId,
    policyVersion: delegation.policyVersion,
    ...(stepUp ? { requiredApproverCapability: "approval:records-export" } : {}),
  } as const;
}

test("SDK correlates fully bound delegated grantor and attenuation denials in core order", async (t) => {
  const laterReasons = [
    "DELEGATION_GRANTOR_MISMATCH",
    "ACTION_OUTSIDE_DELEGATION_SCOPE",
    "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
    "POLICY_DENY",
    "INSUFFICIENT_DELEGATED_CAPABILITY",
    "AFFILIATION_REQUIRED",
    "ACTION_NOT_PERMITTED",
  ] as const;
  const invalidGrantors: readonly { readonly name: string; readonly credential: Credential }[] = [
    { name: "malformed", credential: {} as Credential },
    { name: "scope-invalid", credential: { ...staticCredential, scopeHash: HASH_0 } },
    { name: "not-yet-valid", credential: { ...staticCredential, issuedAt: LATER } },
    {
      name: "expired",
      credential: {
        ...staticCredential,
        issuedAt: "2026-05-31T23:00:00.000Z",
        expiresAt: START,
      },
    },
    {
      name: "issuer-contradictory",
      credential: { ...staticCredential, issuerId: "issuer:other" },
    },
  ];

  for (const invalidGrantor of invalidGrantors) {
    await t.test(`rejects every later reason for ${invalidGrantor.name} grantor authority`, async () => {
      for (const reasonCode of laterReasons) {
        await expectInvalidResponse(() => delegatedDenialClient(
          fullyBoundDelegatedDenial(reasonCode),
        ).evaluate({
          ...delegatedCorrelationInput,
          grantorCredential: invalidGrantor.credential,
        }));
      }
    });
  }

  const stepUpPolicyInput: PolicyInput = {
    id: "policy:static-step-up",
    rules: [{
      action: "records:read",
      actionSensitivity: "SENSITIVE",
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "STEP_UP",
      approverCapability: "approval:records-export",
    }],
  };
  const stepUpPolicy = createPolicy(stepUpPolicyInput);
  const stepUpDelegation = correlatedDelegation({
    policyId: stepUpPolicy.id,
    policyVersion: stepUpPolicy.version,
  });
  const successCases = [
    {
      name: "ALLOW",
      decision: fullyBoundDelegatedSuccess("ALLOW"),
      input: delegatedCorrelationInput,
    },
    {
      name: "STEP_UP",
      decision: fullyBoundDelegatedSuccess("STEP_UP", stepUpDelegation),
      input: {
        ...delegatedCorrelationInput,
        delegation: stepUpDelegation,
        policy: stepUpPolicyInput,
      },
    },
  ] as const;
  for (const successCase of successCases) {
    await t.test(`accepts valid delegated ${successCase.name} positive control`, async () => {
      const evaluated = await delegatedDenialClient(successCase.decision).evaluate(successCase.input);
      assert.equal(evaluated.decision.outcome, successCase.name);
      assert.equal(evaluated.receipt, undefined);
    });
    for (const invalidGrantor of [
      { name: "scope-invalid", credential: { ...staticCredential, scopeHash: HASH_0 } },
      {
        name: "issuer-contradictory",
        credential: correlatedGrantorCredential({ issuerId: "issuer:other" }),
      },
    ] as const) {
      await t.test(`rejects forged ${successCase.name} for ${invalidGrantor.name} grantor`, async () => {
        await expectInvalidResponse(() => delegatedDenialClient(successCase.decision).evaluate({
          ...successCase.input,
          grantorCredential: invalidGrantor.credential,
        }));
      });
    }
  }

  await t.test("contains grantor accessors that become malformed during validation", async () => {
    let actionReads = 0;
    const throwingGrantor = {
      ...staticCredential,
      get allowedActions(): readonly string[] {
        actionReads += 1;
        if (actionReads === 1) return staticCredential.allowedActions;
        throw new Error("RAW_GRANTOR_GETTER_LEAK");
      },
    } as Credential;
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedSuccess("ALLOW"),
    ).evaluate({
      ...delegatedCorrelationInput,
      grantorCredential: throwingGrantor,
    }));
    assert.equal(actionReads, 2);
  });

  await t.test("preserves checkDelegation grantor-invalid before the outer delegate-tuple stage", async () => {
    const mismatchedDelegation = correlatedDelegation({ delegateId: "agent:other" });
    const evaluated = await delegatedDenialClient(fullyBoundDelegatedDenial(
      "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
      mismatchedDelegation,
    )).evaluate({
      ...delegatedCorrelationInput,
      grantorCredential: {} as Credential,
      delegation: mismatchedDelegation,
    });
    assert.equal(evaluated.decision.reasonCode, "DELEGATION_GRANTOR_CREDENTIAL_INVALID");
    assert.equal(evaluated.receipt, undefined);
  });

  const tupleContradictions = [
    {
      name: "credential ID",
      credential: correlatedGrantorCredential({ id: "credential:other-grantor" }),
    },
    {
      name: "principal ID",
      credential: correlatedGrantorCredential({ principalId: "principal:other-grantor" }),
    },
    {
      name: "principal type",
      credential: correlatedGrantorCredential({ principalType: "ORGANIZATION" }),
    },
  ] as const;
  for (const contradiction of tupleContradictions) {
    await t.test(`accepts exact grantor mismatch for ${contradiction.name}`, async () => {
      const evaluated = await delegatedDenialClient(
        fullyBoundDelegatedDenial("DELEGATION_GRANTOR_MISMATCH"),
      ).evaluate({
        ...delegatedCorrelationInput,
        grantorCredential: contradiction.credential,
      });
      assert.equal(evaluated.decision.reasonCode, "DELEGATION_GRANTOR_MISMATCH");
      assert.equal(evaluated.receipt, undefined);
    });

    await t.test(`blocks later stages for mismatched ${contradiction.name}`, async () => {
      for (const reasonCode of [
        "ACTION_OUTSIDE_DELEGATION_SCOPE",
        "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
        "INSUFFICIENT_DELEGATED_CAPABILITY",
      ] as const) {
        await expectInvalidResponse(() => delegatedDenialClient(
          fullyBoundDelegatedDenial(reasonCode),
        ).evaluate({
          ...delegatedCorrelationInput,
          grantorCredential: contradiction.credential,
        }));
      }
    });
  }

  await t.test("rejects false grantor mismatch when the validated tuple matches", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("DELEGATION_GRANTOR_MISMATCH"),
    ).evaluate(delegatedCorrelationInput));
  });

  const grantorWithoutAction = correlatedGrantorCredential({ allowedActions: ["records:other"] });
  const grantorWithDelegatedOtherAction = correlatedGrantorCredential({
    allowedActions: ["records:other", "records:read"],
  });
  const delegationWithoutAction = correlatedDelegation({ allowedActions: ["records:other"] });
  const actionContradictions = [
    {
      name: "grantor credential",
      input: {
        ...delegatedCorrelationInput,
        grantorCredential: grantorWithoutAction,
        delegation: delegationWithoutAction,
      },
      delegation: delegationWithoutAction,
    },
    {
      name: "delegation",
      input: {
        ...delegatedCorrelationInput,
        grantorCredential: grantorWithDelegatedOtherAction,
        delegation: delegationWithoutAction,
      },
      delegation: delegationWithoutAction,
    },
  ] as const;
  for (const contradiction of actionContradictions) {
    await t.test(`accepts action attenuation denial when absent from ${contradiction.name}`, async () => {
      const evaluated = await delegatedDenialClient(fullyBoundDelegatedDenial(
        "ACTION_OUTSIDE_DELEGATION_SCOPE",
        contradiction.delegation,
      )).evaluate(contradiction.input);
      assert.equal(evaluated.decision.reasonCode, "ACTION_OUTSIDE_DELEGATION_SCOPE");
      assert.equal(evaluated.receipt, undefined);
    });

    await t.test(`blocks resource and downstream stages when action is absent from ${contradiction.name}`, async () => {
      for (const reasonCode of [
        "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
        "INSUFFICIENT_DELEGATED_CAPABILITY",
      ] as const) {
        await expectInvalidResponse(() => delegatedDenialClient(fullyBoundDelegatedDenial(
          reasonCode,
          contradiction.delegation,
        )).evaluate(contradiction.input));
      }
    });
  }

  await t.test("rejects false action attenuation denial when action is in both scopes", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("ACTION_OUTSIDE_DELEGATION_SCOPE"),
    ).evaluate(delegatedCorrelationInput));
  });

  const grantorWithoutResource = correlatedGrantorCredential({
    allowedResourceIds: ["record:other"],
  });
  const grantorWithDelegatedOtherResource = correlatedGrantorCredential({
    allowedResourceIds: ["record:other", RESOURCE],
  });
  const delegationWithoutResource = correlatedDelegation({
    allowedResourceIds: ["record:other"],
  });
  const resourceContradictions = [
    {
      name: "grantor credential",
      input: {
        ...delegatedCorrelationInput,
        grantorCredential: grantorWithoutResource,
        delegation: delegationWithoutResource,
      },
      delegation: delegationWithoutResource,
    },
    {
      name: "delegation",
      input: {
        ...delegatedCorrelationInput,
        grantorCredential: grantorWithDelegatedOtherResource,
        delegation: delegationWithoutResource,
      },
      delegation: delegationWithoutResource,
    },
  ] as const;
  for (const contradiction of resourceContradictions) {
    await t.test(`accepts resource attenuation denial when absent from ${contradiction.name}`, async () => {
      const evaluated = await delegatedDenialClient(fullyBoundDelegatedDenial(
        "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
        contradiction.delegation,
      )).evaluate(contradiction.input);
      assert.equal(evaluated.decision.reasonCode, "RESOURCE_OUTSIDE_DELEGATION_SCOPE");
      assert.equal(evaluated.receipt, undefined);
    });

    await t.test(`blocks downstream stages when resource is absent from ${contradiction.name}`, async () => {
      await expectInvalidResponse(() => delegatedDenialClient(fullyBoundDelegatedDenial(
        "INSUFFICIENT_DELEGATED_CAPABILITY",
        contradiction.delegation,
      )).evaluate(contradiction.input));
    });
  }

  await t.test("rejects false resource attenuation denial when resource is in both scopes", async () => {
    await expectInvalidResponse(() => delegatedDenialClient(
      fullyBoundDelegatedDenial("RESOURCE_OUTSIDE_DELEGATION_SCOPE"),
    ).evaluate(delegatedCorrelationInput));
  });
});

interface DelegatedFinalPolicyFixtureOptions {
  readonly delegationCapabilities?: readonly string[];
  readonly delegationAllowedActions?: readonly string[];
  readonly delegationAllowedResourceIds?: readonly string[];
  readonly delegationIssuedAt?: string;
  readonly delegationExpiresAt?: string;
  readonly credentialCapabilities?: readonly string[];
  readonly credentialAffiliations?: Credential["affiliations"];
  readonly grantorCapabilities?: readonly string[];
  readonly grantorAllowedActions?: readonly string[];
  readonly grantorAllowedResourceIds?: readonly string[];
  readonly grantorIssuedAt?: string;
  readonly grantorExpiresAt?: string;
  readonly unverifiedMetadata?: Credential["unverifiedMetadata"];
}

function delegatedFinalPolicyFixture(
  reasonCode: string,
  policyInput: PolicyInput,
  options: DelegatedFinalPolicyFixtureOptions = {},
) {
  const canonical = createPolicy(policyInput);
  const affiliations = options.credentialAffiliations ?? delegatedCorrelationCredential.affiliations;
  const credentialScope = {
    capabilities: options.credentialCapabilities ?? delegatedCorrelationCredential.capabilities,
    allowedActions: delegatedCorrelationCredential.allowedActions,
    allowedResourceIds: delegatedCorrelationCredential.allowedResourceIds,
  };
  const credential: Credential = {
    ...delegatedCorrelationCredential,
    ...credentialScope,
    affiliations,
    scopeHash: computeScopeHash(credentialScope),
    ...(options.unverifiedMetadata === undefined
      ? {}
      : { unverifiedMetadata: options.unverifiedMetadata }),
  };
  const delegation = correlatedDelegation({
    policyId: canonical.id,
    policyVersion: canonical.version,
    capabilities: options.delegationCapabilities ?? delegatedCorrelationDelegation.capabilities,
    allowedActions: options.delegationAllowedActions ?? delegatedCorrelationDelegation.allowedActions,
    allowedResourceIds: options.delegationAllowedResourceIds ??
      delegatedCorrelationDelegation.allowedResourceIds,
    issuedAt: options.delegationIssuedAt ?? delegatedCorrelationDelegation.issuedAt,
    expiresAt: options.delegationExpiresAt ?? delegatedCorrelationDelegation.expiresAt,
  });
  const grantorCredential = correlatedGrantorCredential({
    capabilities: options.grantorCapabilities ?? staticCredential.capabilities,
    allowedActions: options.grantorAllowedActions ?? staticCredential.allowedActions,
    allowedResourceIds: options.grantorAllowedResourceIds ?? staticCredential.allowedResourceIds,
    issuedAt: options.grantorIssuedAt ?? staticCredential.issuedAt,
    expiresAt: options.grantorExpiresAt ?? staticCredential.expiresAt,
  });
  const decision = {
    ...fullyBoundDelegatedDenial(reasonCode, delegation, credential),
    policyId: canonical.id,
    policyVersion: canonical.version,
  };
  const input = {
    ...delegatedCorrelationInput,
    principal: { ...delegatedCorrelationPrincipal, affiliations },
    delegateIdentityCredential: credential,
    grantorCredential,
    delegation,
    policy: policyInput,
  };
  return { decision, input };
}

test("SDK correlates fully bound delegated final policy denials in core order", async (t) => {
  const allowRule = {
    action: "records:read",
    actionSensitivity: "ROUTINE" as const,
    requiredCapabilities: ["records:read"],
    requiredAffiliations: [] as const,
    effect: "ALLOW" as const,
  };
  const finalPolicy = (id: string, rules: PolicyInput["rules"]): PolicyInput => ({ id, rules });
  const expectAccepted = async (
    reasonCode: string,
    fixture: ReturnType<typeof delegatedFinalPolicyFixture>,
  ) => {
    const evaluated = await delegatedDenialClient(fixture.decision).evaluate(fixture.input);
    assert.equal(evaluated.decision.reasonCode, reasonCode);
    assert.equal(evaluated.decision.requiredApproverCapability, undefined);
    assert.equal(evaluated.receipt, undefined);
  };

  await t.test("accepts ACTION_NOT_PERMITTED only when the exact action rule is absent", async () => {
    const absent = delegatedFinalPolicyFixture(
      "ACTION_NOT_PERMITTED",
      finalPolicy("policy:delegated-final-action-absent", [{
        ...allowRule,
        action: "records:other",
      }]),
    );
    await expectAccepted("ACTION_NOT_PERMITTED", absent);
    for (const reasonCode of [
      "POLICY_DENY",
      "INSUFFICIENT_DELEGATED_CAPABILITY",
      "AFFILIATION_REQUIRED",
    ] as const) {
      await expectInvalidResponse(() => delegatedDenialClient({
        ...absent.decision,
        reasonCode,
      }).evaluate(absent.input));
    }

    const present = delegatedFinalPolicyFixture(
      "ACTION_NOT_PERMITTED",
      finalPolicy("policy:delegated-final-action-present", [allowRule]),
    );
    await expectInvalidResponse(() => delegatedDenialClient(present.decision).evaluate(present.input));
  });

  await t.test("preserves ROUTINE fallback sensitivity for an absent action rule", async () => {
    const fixture = delegatedFinalPolicyFixture(
      "ACTION_NOT_PERMITTED",
      finalPolicy("policy:delegated-final-action-fallback", [{
        ...allowRule,
        action: "records:other",
        actionSensitivity: "CRITICAL",
      }]),
    );
    await expectAccepted("ACTION_NOT_PERMITTED", fixture);
  });

  await t.test("rejects every normal final reason when rule sensitivity contradicts the decision", async () => {
    const fixture = delegatedFinalPolicyFixture(
      "INSUFFICIENT_DELEGATED_CAPABILITY",
      finalPolicy("policy:delegated-final-sensitive", [{
        ...allowRule,
        actionSensitivity: "SENSITIVE",
        requiredCapabilities: ["records:missing"],
      }]),
      { delegationCapabilities: ["records:other"] },
    );
    await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
  });

  await t.test("accepts POLICY_DENY only for an exact DENY rule", async () => {
    const deny = delegatedFinalPolicyFixture(
      "POLICY_DENY",
      finalPolicy("policy:delegated-final-deny", [{ ...allowRule, effect: "DENY" }]),
    );
    await expectAccepted("POLICY_DENY", deny);

    const allow = delegatedFinalPolicyFixture(
      "POLICY_DENY",
      finalPolicy("policy:delegated-final-false-deny", [allowRule]),
    );
    await expectInvalidResponse(() => delegatedDenialClient(allow.decision).evaluate(allow.input));
  });

  await t.test("blocks every later reason after an exact DENY rule", async () => {
    for (const reasonCode of [
      "INSUFFICIENT_DELEGATED_CAPABILITY",
      "AFFILIATION_REQUIRED",
    ] as const) {
      const fixture = delegatedFinalPolicyFixture(
        reasonCode,
        finalPolicy(`policy:delegated-final-deny-blocks-${reasonCode.toLowerCase()}`, [{
          ...allowRule,
          effect: "DENY",
          requiredCapabilities: ["records:missing"],
          requiredAffiliations: [{ organizationId: "organization:missing", role: "member" }],
        }]),
        { delegationCapabilities: ["records:other"] },
      );
      await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
    }
  });

  await t.test("rejects terminal denials for impossible delegation issuance attenuation", async () => {
    const contradictions: readonly {
      readonly name: string;
      readonly options: DelegatedFinalPolicyFixtureOptions;
    }[] = [
      {
        name: "capability escalation",
        options: {
          delegationCapabilities: ["records:extra", "records:read"],
          grantorCapabilities: ["records:read"],
        },
      },
      {
        name: "action escalation",
        options: {
          delegationAllowedActions: ["records:other", "records:read"],
          grantorAllowedActions: ["records:read"],
        },
      },
      {
        name: "resource escalation",
        options: {
          delegationAllowedResourceIds: ["record:other", RESOURCE],
          grantorAllowedResourceIds: [RESOURCE],
        },
      },
      {
        name: "redelegation capability",
        options: {
          delegationCapabilities: ["delegation:issue", "records:read"],
          grantorCapabilities: ["delegation:issue", "records:read"],
        },
      },
      {
        name: "delegation predates grantor authority",
        options: {
          delegationIssuedAt: "2026-05-31T23:59:00.000Z",
          grantorIssuedAt: START,
        },
      },
      {
        name: "delegation outlives grantor authority",
        options: {
          delegationExpiresAt: EXPIRY,
          grantorExpiresAt: ARTIFACT_EXPIRY,
        },
      },
    ];
    for (const contradiction of contradictions) {
      const fixture = delegatedFinalPolicyFixture(
        "POLICY_DENY",
        finalPolicy(`policy:delegated-final-attenuation-${contradiction.name.replaceAll(" ", "-")}`, [{
          ...allowRule,
          effect: "DENY",
        }]),
        contradiction.options,
      );
      await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
    }
  });

  await t.test("uses only delegated capabilities for one or multiple missing requirements", async () => {
    for (const requiredCapabilities of [
      ["records:read", "records:write"],
      ["records:delete", "records:read", "records:write"],
    ] as const) {
      const fixture = delegatedFinalPolicyFixture(
        "INSUFFICIENT_DELEGATED_CAPABILITY",
        finalPolicy(`policy:delegated-final-caps-${requiredCapabilities.length}`, [{
          ...allowRule,
          requiredCapabilities,
        }]),
        {
          delegationCapabilities: ["records:read"],
          credentialCapabilities: [...requiredCapabilities, "identity:act"].sort(),
          grantorCapabilities: [...requiredCapabilities].sort(),
        },
      );
      await expectAccepted("INSUFFICIENT_DELEGATED_CAPABILITY", fixture);
    }
  });

  await t.test("rejects false capability denial when delegation satisfies all requirements", async () => {
    const fixture = delegatedFinalPolicyFixture(
      "INSUFFICIENT_DELEGATED_CAPABILITY",
      finalPolicy("policy:delegated-final-caps-satisfied", [{
        ...allowRule,
        requiredCapabilities: ["records:read", "records:write"],
      }]),
      {
        delegationCapabilities: ["records:read", "records:write"],
        grantorCapabilities: ["records:read", "records:write"],
      },
    );
    await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
  });

  await t.test("blocks affiliation denial while a delegated capability is missing", async () => {
    const fixture = delegatedFinalPolicyFixture(
      "AFFILIATION_REQUIRED",
      finalPolicy("policy:delegated-final-cap-before-affiliation", [{
        ...allowRule,
        requiredCapabilities: ["records:missing"],
        requiredAffiliations: [{ organizationId: "organization:required", role: "member" }],
      }]),
      { delegationCapabilities: ["records:other"], credentialAffiliations: [] },
    );
    await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
  });

  await t.test("accepts affiliation denial for missing organization, role, or one of multiple tuples", async () => {
    const cases = [
      {
        name: "organization",
        held: [{ organizationId: "organization:held", role: "member" }],
        required: [{ organizationId: "organization:missing", role: "member" }],
      },
      {
        name: "role",
        held: [{ organizationId: "organization:held", role: "member" }],
        required: [{ organizationId: "organization:held", role: "admin" }],
      },
      {
        name: "one-of-multiple",
        held: [{ organizationId: "organization:a", role: "member" }],
        required: [
          { organizationId: "organization:a", role: "member" },
          { organizationId: "organization:b", role: "reviewer" },
        ],
      },
    ] as const;
    for (const control of cases) {
      const fixture = delegatedFinalPolicyFixture(
        "AFFILIATION_REQUIRED",
        finalPolicy(`policy:delegated-final-affiliation-${control.name}`, [{
          ...allowRule,
          requiredAffiliations: control.required,
        }]),
        { credentialAffiliations: control.held },
      );
      await expectAccepted("AFFILIATION_REQUIRED", fixture);
    }
  });

  await t.test("rejects false affiliation denial when exact canonical tuples satisfy in any policy order", async () => {
    const held = [
      { organizationId: "organization:a", role: "member" },
      { organizationId: "organization:b", role: "reviewer" },
    ] as const;
    const fixture = delegatedFinalPolicyFixture(
      "AFFILIATION_REQUIRED",
      finalPolicy("policy:delegated-final-affiliation-satisfied", [{
        ...allowRule,
        requiredAffiliations: [...held].reverse(),
      }]),
      { credentialAffiliations: held },
    );
    await expectInvalidResponse(() => delegatedDenialClient(fixture.decision).evaluate(fixture.input));
  });

  await t.test("rejects downstream final denials after ALLOW or STEP_UP prerequisites satisfy", async () => {
    for (const effect of ["ALLOW", "STEP_UP"] as const) {
      for (const reasonCode of [
        "INSUFFICIENT_DELEGATED_CAPABILITY",
        "AFFILIATION_REQUIRED",
      ] as const) {
        const fixture = delegatedFinalPolicyFixture(
          reasonCode,
          finalPolicy(`policy:delegated-final-${effect.toLowerCase()}-${reasonCode.toLowerCase()}`, [{
            ...allowRule,
            effect,
            ...(effect === "STEP_UP"
              ? { actionSensitivity: "SENSITIVE" as const, approverCapability: "approval:records" }
              : {}),
          }]),
        );
        const decision = effect === "STEP_UP"
          ? { ...fixture.decision, actionSensitivity: "SENSITIVE" as const }
          : fixture.decision;
        await expectInvalidResponse(() => delegatedDenialClient(decision).evaluate(fixture.input));
      }
    }
  });

  await t.test("rejects forged requiredApproverCapability on DENY at the runtime-schema boundary", async () => {
    const fixture = delegatedFinalPolicyFixture(
      "POLICY_DENY",
      finalPolicy("policy:delegated-final-forged-approver", [{ ...allowRule, effect: "DENY" }]),
    );
    await expectInvalidResponse(() => delegatedDenialClient({
      ...fixture.decision,
      requiredApproverCapability: "approval:forged",
    }).evaluate(fixture.input));
  });

  await t.test("accepts exact credential metadata and rejects an altered contextual proof ID", async () => {
    const metadata = {
      zkPassProofId: "proof:zkpass:delegated-final",
      contextualProofIds: ["proof:context:a", "proof:context:b"],
    } as const;
    const fixture = delegatedFinalPolicyFixture(
      "POLICY_DENY",
      finalPolicy("policy:delegated-final-metadata", [{ ...allowRule, effect: "DENY" }]),
      { unverifiedMetadata: metadata },
    );
    await expectAccepted("POLICY_DENY", fixture);
    await expectInvalidResponse(() => delegatedDenialClient({
      ...fixture.decision,
      unverifiedMetadata: {
        ...metadata,
        contextualProofIds: ["proof:context:a", "proof:context:altered"],
      },
    }).evaluate(fixture.input));
  });
});

test("SDK preserves a validated grantor credential snapshot for later fully bound denials", async () => {
  const grantorWithoutResource = correlatedGrantorCredential({
    allowedResourceIds: ["record:other"],
  });
  const delegationWithoutResource = correlatedDelegation({
    allowedResourceIds: ["record:other"],
  });
  let actionReads = 0;
  const accessorGrantorCredential = {
    ...grantorWithoutResource,
    get allowedActions(): readonly string[] {
      actionReads += 1;
      return actionReads <= 2 ? grantorWithoutResource.allowedActions : [];
    },
  } as Credential;
  const evaluated = await delegatedDenialClient(
    fullyBoundDelegatedDenial("RESOURCE_OUTSIDE_DELEGATION_SCOPE", delegationWithoutResource),
  ).evaluate({
    ...delegatedCorrelationInput,
    grantorCredential: accessorGrantorCredential,
    delegation: delegationWithoutResource,
  });

  assert.equal(evaluated.decision.reasonCode, "RESOURCE_OUTSIDE_DELEGATION_SCOPE");
  assert.equal(evaluated.receipt, undefined);
  assert.equal(actionReads, 2);
});

test("SDK preserves a validated delegation snapshot for fully bound denials", async () => {
  let idReads = 0;
  const accessorDelegation = {
    ...delegatedCorrelationDelegation,
    get id(): string {
      idReads += 1;
      return idReads <= 2 ? delegatedCorrelationDelegation.id : "delegation:mutated-after-validation";
    },
  } as CapabilityDelegation;
  const evaluated = await delegatedDenialClient(
    fullyBoundDelegatedDenial("DELEGATION_REVOKED"),
  ).evaluate({ ...delegatedCorrelationInput, delegation: accessorDelegation });

  assert.equal(evaluated.decision.reasonCode, "DELEGATION_REVOKED");
  assert.equal(evaluated.decision.delegationId, delegatedCorrelationDelegation.id);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK preserves a validated delegated credential snapshot after caller mutation", async () => {
  let idReads = 0;
  const accessorCredential = {
    ...delegatedCorrelationCredential,
    get id(): string {
      idReads += 1;
      return idReads <= 2 ? delegatedCorrelationCredential.id : "credential:mutated-after-validation";
    },
  } as Credential;
  const evaluated = await delegatedDenialClient({
    ...delegatedActingOnlyDenyDecision,
    reasonCode: "CREDENTIAL_REVOKED",
  }).evaluate({
    ...delegatedCorrelationInput,
    delegateIdentityCredential: accessorCredential,
  });

  assert.equal(evaluated.decision.reasonCode, "CREDENTIAL_REVOKED");
  assert.equal(evaluated.decision.actingCredentialId, delegatedCorrelationCredential.id);
  assert.equal(evaluated.receipt, undefined);
});

test("SDK rejects accessor-backed credential mutation after validation without leaking raw errors", async () => {
  let capabilityReads = 0;
  const accessorCredential = {
    ...staticCredential,
    get capabilities(): readonly string[] {
      capabilityReads += 1;
      return capabilityReads <= 2 ? staticCredential.capabilities : null as unknown as readonly string[];
    },
  } as Credential;
  const decision = {
    ...staticBoundDirectDenyDecision,
    reasonCode: "INSUFFICIENT_CAPABILITY",
  } as const;
  const client = new ZkycReferenceClient({
    baseUrl: "https://mutable-caller-artifact.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:mutable-caller-artifact",
      decision,
    })),
  });

  await expectInvalidResponse(() => client.evaluate({
    ...staticDirectEvaluationInput,
    credential: accessorCredential,
  }));
});

test("SDK enforces direct credential precedence before policy-stage denials", async (t) => {
  const denyPolicyInput = policy("DENY", staticDirectEvaluationInput.action);
  const denyPolicy = createPolicy(denyPolicyInput);
  const actionNotPermittedAction = "records:write";
  const actionNotPermittedCredentialScope = {
    capabilities: staticCredential.capabilities,
    allowedActions: [staticDirectEvaluationInput.action, actionNotPermittedAction],
    allowedResourceIds: staticCredential.allowedResourceIds,
  } as const;
  const actionNotPermittedCredential: Credential = {
    ...staticCredential,
    ...actionNotPermittedCredentialScope,
    scopeHash: computeScopeHash(actionNotPermittedCredentialScope),
  };
  const policyStages = [
    {
      reasonCode: "POLICY_DENY",
      policy: denyPolicyInput,
      policyVersion: denyPolicy.version,
      action: staticDirectEvaluationInput.action,
      credential: staticCredential,
    },
    {
      reasonCode: "ACTION_NOT_PERMITTED",
      policy: staticPolicyInput,
      policyVersion: staticPolicy.version,
      action: actionNotPermittedAction,
      credential: actionNotPermittedCredential,
    },
  ] as const;

  for (const stage of policyStages) {
    const input = {
      ...staticDirectEvaluationInput,
      action: stage.action,
      policy: stage.policy,
      credential: stage.credential,
    };
    const decision = {
      ...staticBoundDirectDenyDecision,
      reasonCode: stage.reasonCode,
      action: stage.action,
      policyId: stage.policy.id,
      policyVersion: stage.policyVersion,
      actingCredentialId: stage.credential.id,
      effectiveScopeHash: stage.credential.scopeHash,
      credentialId: stage.credential.id,
    };
    const clientFor = (responseDecision: unknown) => new ZkycReferenceClient({
      baseUrl: "https://policy-stage.reference",
      fetch: () => Promise.resolve(jsonResponse({
        logId: `decision-log:${stage.reasonCode.toLowerCase()}`,
        decision: responseDecision,
      })),
    });

    await t.test(`${stage.reasonCode} accepted after all earlier stages pass`, async () => {
      const evaluated = await clientFor(decision).evaluate(input);
      assert.equal(evaluated.decision.reasonCode, stage.reasonCode);
      assert.equal(evaluated.receipt, undefined);
    });

    const malformedCredential = {
      ...stage.credential,
      capabilities: null,
    } as unknown as Credential;
    const earlierStageContradictions: readonly {
      readonly name: string;
      readonly credential: Credential;
    }[] = [
      { name: "malformed", credential: malformedCredential },
      { name: "not yet valid", credential: { ...stage.credential, issuedAt: LATER } },
      { name: "expired", credential: { ...stage.credential, expiresAt: START } },
      {
        name: "subject mismatch",
        credential: { ...stage.credential, principalId: "principal:other" },
      },
      {
        name: "action outside scope",
        credential: {
          ...stage.credential,
          allowedActions: [],
          scopeHash: computeScopeHash({
            capabilities: stage.credential.capabilities,
            allowedActions: [],
            allowedResourceIds: stage.credential.allowedResourceIds,
          }),
        },
      },
      {
        name: "resource outside scope",
        credential: {
          ...stage.credential,
          allowedResourceIds: [],
          scopeHash: computeScopeHash({
            capabilities: stage.credential.capabilities,
            allowedActions: stage.credential.allowedActions,
            allowedResourceIds: [],
          }),
        },
      },
    ];

    for (const contradiction of earlierStageContradictions) {
      await t.test(`${stage.reasonCode} rejects ${contradiction.name} credential`, async () => {
        const forgedDecision = {
          ...decision,
          actingCredentialId: contradiction.credential.id,
          effectiveScopeHash: contradiction.credential.scopeHash,
          credentialId: contradiction.credential.id,
        };
        await expectInvalidResponse(() => clientFor(forgedDecision).evaluate({
          ...input,
          credential: contradiction.credential,
        }));
      });
    }
  }
});

test("SDK rejects issueDelegation responses correlated to forged request or credential facts", async (t) => {
  const grantor: Principal = {
    id: "principal:delegation-grantor",
    type: "HUMAN",
    affiliations: [
      { organizationId: "organization:zeta", role: "member" },
      { organizationId: "organization:alpha", role: "admin" },
    ],
  };
  const canonicalGrantorAffiliations = [...grantor.affiliations].reverse();
  const delegate: Principal = {
    id: "agent:delegation-delegate",
    type: "AGENT",
    affiliations: [],
  };
  const grantorCredentialScope = {
    capabilities: ["delegation:issue", "records:read", "records:write"],
    allowedActions: ["records:read", "records:write"],
    allowedResourceIds: [RESOURCE, "record:other"],
  } as const;
  const grantorCredential: Credential = {
    version: 2,
    id: "credential:delegation-grantor",
    issuerId: "issuer:delegation",
    principalId: grantor.id,
    principalType: grantor.type,
    affiliations: canonicalGrantorAffiliations,
    ...grantorCredentialScope,
    issuedAt: START,
    expiresAt: EXPIRY,
    scopeHash: computeScopeHash(grantorCredentialScope),
  };
  const delegatedScope = {
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
  } as const;
  const issueInput: IssueDelegationRequest = {
    grantor,
    grantorCredential,
    delegate,
    policy: staticPolicyInput,
    ...delegatedScope,
    expiresAt: ARTIFACT_EXPIRY,
  };
  const delegationSeed: CapabilityDelegation = {
    version: 1,
    id: "delegation:correlated",
    issuerId: grantorCredential.issuerId,
    grantorCredentialId: grantorCredential.id,
    grantorId: grantor.id,
    grantorType: grantor.type,
    delegateId: delegate.id,
    delegateType: delegate.type,
    policyId: staticPolicy.id,
    policyVersion: staticPolicy.version,
    ...delegatedScope,
    issuedAt: START,
    expiresAt: ARTIFACT_EXPIRY,
    scopeHash: computeScopeHash(delegatedScope),
    delegationBindingHash: HASH_0,
  };
  const rebind = (delegation: CapabilityDelegation): CapabilityDelegation => ({
    ...delegation,
    delegationBindingHash: computeDelegationBindingHash(delegation as never),
  });
  const forge = (
    overrides: Partial<CapabilityDelegation>,
    recomputeScopeHash = false,
  ): CapabilityDelegation => {
    const altered = { ...delegationSeed, ...overrides };
    const scoped = recomputeScopeHash
      ? {
        ...altered,
        scopeHash: computeScopeHash({
          capabilities: altered.capabilities,
          allowedActions: altered.allowedActions,
          allowedResourceIds: altered.allowedResourceIds,
        }),
      }
      : altered;
    return rebind(scoped);
  };
  const validDelegation = rebind(delegationSeed);
  const clientFor = (delegation: CapabilityDelegation) => new ZkycReferenceClient({
    baseUrl: "https://delegation-correlation.reference",
    fetch: () => Promise.resolve(jsonResponse({ delegation }, 201)),
  });

  assert.equal(
    (await clientFor(validDelegation).issueDelegation(issueInput)).delegation.id,
    validDelegation.id,
  );

  const inputForgeries: readonly {
    readonly name: string;
    readonly input: IssueDelegationRequest;
  }[] = [
    {
      name: "grantor credential principal ID",
      input: {
        ...issueInput,
        grantorCredential: { ...grantorCredential, principalId: "principal:forged" },
      },
    },
    {
      name: "grantor credential principal type",
      input: {
        ...issueInput,
        grantorCredential: { ...grantorCredential, principalType: "ORGANIZATION" },
      },
    },
    {
      name: "canonical grantor credential affiliations",
      input: {
        ...issueInput,
        grantorCredential: {
          ...grantorCredential,
          affiliations: [{ organizationId: "organization:forged", role: "admin" }],
        },
      },
    },
    {
      name: "grantor credential scope hash integrity",
      input: { ...issueInput, grantorCredential: { ...grantorCredential, scopeHash: HASH_0 } },
    },
  ];
  for (const forgery of inputForgeries) {
    await t.test(forgery.name, async () => {
      await expectInvalidResponse(() => clientFor(validDelegation).issueDelegation(forgery.input));
    });
  }

  const responseForgeries: readonly {
    readonly name: string;
    readonly delegation: CapabilityDelegation;
  }[] = [
    { name: "grantor principal ID", delegation: forge({ grantorId: "principal:forged" }) },
    { name: "grantor principal type", delegation: forge({ grantorType: "ORGANIZATION" }) },
    {
      name: "grantor credential ID",
      delegation: forge({ grantorCredentialId: "credential:forged" }),
    },
    { name: "delegate ID", delegation: forge({ delegateId: "agent:forged" }) },
    { name: "delegate type", delegation: forge({ delegateType: "ORGANIZATION" }) },
    { name: "policy ID", delegation: forge({ policyId: "policy:forged" }) },
    { name: "policy version", delegation: forge({ policyVersion: HASH_0 }) },
    {
      name: "canonical capabilities",
      delegation: forge({ capabilities: ["records:write"] }, true),
    },
    {
      name: "canonical allowed actions",
      delegation: forge({ allowedActions: ["records:write"] }, true),
    },
    {
      name: "canonical allowed resource IDs",
      delegation: forge({ allowedResourceIds: ["record:other"] }, true),
    },
    { name: "delegation scope hash", delegation: forge({ scopeHash: HASH_0 }) },
    {
      name: "delegation binding hash",
      delegation: { ...validDelegation, delegationBindingHash: HASH_0 },
    },
    { name: "expiry", delegation: forge({ expiresAt: EXPIRY }) },
    { name: "issuer", delegation: forge({ issuerId: "issuer:forged" }) },
  ];
  for (const forgery of responseForgeries) {
    await t.test(forgery.name, async () => {
      await expectInvalidResponse(() => clientFor(forgery.delegation).issueDelegation(issueInput));
    });
  }
});

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

  const credentialScopeClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      credential: { ...staticCredential, allowedResourceIds: ["record:other"] },
    }, 201)),
  });
  await expectInvalidResponse(() => credentialScopeClient.issueCredential({
    principal: human,
    capabilities: staticCredential.capabilities,
    allowedActions: staticCredential.allowedActions,
    allowedResourceIds: staticCredential.allowedResourceIds,
    expiresAt: staticCredential.expiresAt,
  }));

  const credentialInput = {
    principal: human,
    capabilities: staticCredential.capabilities,
    allowedActions: staticCredential.allowedActions,
    allowedResourceIds: staticCredential.allowedResourceIds,
    expiresAt: staticCredential.expiresAt,
  } as const;
  const validCredentialClient = new ZkycReferenceClient({
    baseUrl: "https://valid.reference",
    fetch: () => Promise.resolve(jsonResponse({ credential: staticCredential }, 201)),
  });
  assert.equal((await validCredentialClient.issueCredential(credentialInput)).credential.scopeHash, staticScopeHash);

  const forgedScopeClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      credential: { ...staticCredential, scopeHash: HASH_0 },
    }, 201)),
  });
  await expectInvalidResponse(() => forgedScopeClient.issueCredential(credentialInput));

  const evaluationInput = {
    authorityMode: "DIRECT",
    principal: human,
    credential: staticCredential,
    action: staticDecision.action,
    resourceId: staticDecision.resourceId,
    actionContext: {},
    policy: staticPolicyInput,
    issueReceipt: false,
  } as const;
  const validEvaluationClient = new ZkycReferenceClient({
    baseUrl: "https://valid.reference",
    fetch: () => Promise.resolve(jsonResponse({ logId: "decision-log:valid", decision: staticDecision })),
  });
  assert.equal((await validEvaluationClient.evaluate(evaluationInput)).decision.outcome, "ALLOW");

  const denyPolicyInput = policy("DENY", staticDecision.action);
  const denyPolicy = createPolicy(denyPolicyInput);
  for (const invalidDecision of [
    { ...staticDecision, contextHash: HASH_0 },
    { ...staticDecision, policyVersion: HASH_1 },
    { ...staticDecision, policyId: denyPolicy.id, policyVersion: denyPolicy.version },
  ]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({ logId: "decision-log:forged", decision: invalidDecision })),
    });
    await expectInvalidResponse(() => client.evaluate({
      ...evaluationInput,
      ...(invalidDecision.policyId === denyPolicy.id ? { policy: denyPolicyInput } : {}),
    }));
  }

  for (const unsatisfiedPolicyInput of [
    {
      id: "policy:requires-admin",
      rules: [{
        action: staticDecision.action,
        actionSensitivity: "ROUTINE" as const,
        requiredCapabilities: ["admin"],
        requiredAffiliations: [],
        effect: "ALLOW" as const,
      }],
    },
    {
      id: "policy:requires-affiliation",
      rules: [{
        action: staticDecision.action,
        actionSensitivity: "ROUTINE" as const,
        requiredCapabilities: ["records:read"],
        requiredAffiliations: [{ organizationId: "organization:required", role: "member" }],
        effect: "ALLOW" as const,
      }],
    },
  ]) {
    const unsatisfiedPolicy = createPolicy(unsatisfiedPolicyInput);
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({
        logId: "decision-log:forged-policy-satisfaction",
        decision: {
          ...staticDecision,
          policyId: unsatisfiedPolicy.id,
          policyVersion: unsatisfiedPolicy.version,
        },
      })),
    });
    await expectInvalidResponse(() => client.evaluate({
      ...evaluationInput,
      policy: unsatisfiedPolicyInput,
    }));
  }

  const mismatchedAffiliationPrincipal: Principal = {
    ...human,
    affiliations: [{ organizationId: "organization:caller", role: "member" }],
  };
  const mismatchedPrincipalClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:forged-principal-affiliation",
      decision: staticDecision,
    })),
  });
  await expectInvalidResponse(() => mismatchedPrincipalClient.evaluate({
    ...evaluationInput,
    principal: mismatchedAffiliationPrincipal,
  }));

  const expiredCredential: Credential = {
    ...staticCredential,
    issuedAt: "2026-05-31T23:00:00.000Z",
    expiresAt: START,
  };
  const expiredCredentialClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:forged-expired-authority",
      decision: staticDecision,
    })),
  });
  await expectInvalidResponse(() => expiredCredentialClient.evaluate({
    ...evaluationInput,
    credential: expiredCredential,
  }));

  const missingRequestedReceiptClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:missing-requested-receipt",
      decision: staticDecision,
    })),
  });
  await expectInvalidResponse(() => missingRequestedReceiptClient.evaluate({
    ...evaluationInput,
    issueReceipt: true,
    receiptExpiresAt: ARTIFACT_EXPIRY,
  }));

  const escalationDelegate: Principal = {
    id: "agent:escalation-probe",
    type: "AGENT",
    affiliations: [],
  };
  const delegateIdentityScope = {
    capabilities: [] as readonly string[],
    allowedActions: [] as readonly string[],
    allowedResourceIds: [] as readonly string[],
  };
  const escalationDelegateCredential: Credential = {
    version: 2,
    id: "credential:escalation-delegate",
    issuerId: staticCredential.issuerId,
    principalId: escalationDelegate.id,
    principalType: escalationDelegate.type,
    affiliations: [],
    ...delegateIdentityScope,
    issuedAt: START,
    expiresAt: EXPIRY,
    scopeHash: computeScopeHash(delegateIdentityScope),
  };
  const escalationPolicyInput: PolicyInput = {
    id: "policy:delegation-escalation-probe",
    rules: [{
      action: "records:read",
      actionSensitivity: "ROUTINE",
      requiredCapabilities: ["admin"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  };
  const escalationPolicy = createPolicy(escalationPolicyInput);
  const escalationScope = {
    capabilities: ["admin"],
    allowedActions: ["records:read"],
    allowedResourceIds: [RESOURCE],
  } as const;
  const escalationDelegationSeed: CapabilityDelegation = {
    version: 1,
    id: "delegation:escalation-probe",
    issuerId: staticCredential.issuerId,
    grantorCredentialId: staticCredential.id,
    grantorId: human.id,
    grantorType: human.type,
    delegateId: escalationDelegate.id,
    delegateType: escalationDelegate.type,
    policyId: escalationPolicy.id,
    policyVersion: escalationPolicy.version,
    ...escalationScope,
    issuedAt: START,
    expiresAt: EXPIRY,
    scopeHash: computeScopeHash(escalationScope),
    delegationBindingHash: HASH_0,
  };
  const escalationDelegation: CapabilityDelegation = {
    ...escalationDelegationSeed,
    delegationBindingHash: computeDelegationBindingHash(escalationDelegationSeed as never),
  };
  const escalationIssueClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({ delegation: escalationDelegation }, 201)),
  });
  await expectInvalidResponse(() => escalationIssueClient.issueDelegation({
    grantor: human,
    grantorCredential: staticCredential,
    delegate: escalationDelegate,
    policy: escalationPolicyInput,
    ...escalationScope,
    expiresAt: EXPIRY,
  }));

  const forgedDelegatedDecision: AccessDecision = {
    version: 2,
    outcome: "ALLOW",
    reasonCode: "POLICY_ALLOW",
    authorityMode: "DELEGATED",
    subjectId: escalationDelegate.id,
    subjectType: escalationDelegate.type,
    actingCredentialId: escalationDelegateCredential.id,
    effectiveScopeHash: escalationDelegation.scopeHash,
    action: "records:read",
    actionSensitivity: "ROUTINE",
    resourceId: RESOURCE,
    contextHash: emptyContextHash,
    policyId: escalationPolicy.id,
    policyVersion: escalationPolicy.version,
    decidedAt: START,
    grantorId: human.id,
    grantorType: human.type,
    grantorCredentialId: staticCredential.id,
    delegationId: escalationDelegation.id,
    delegationBindingHash: escalationDelegation.delegationBindingHash,
  };
  const escalationEvaluationClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:delegation-escalation-probe",
      decision: forgedDelegatedDecision,
    })),
  });
  await expectInvalidResponse(() => escalationEvaluationClient.evaluate({
    authorityMode: "DELEGATED",
    principal: escalationDelegate,
    delegateIdentityCredential: escalationDelegateCredential,
    grantorCredential: staticCredential,
    delegation: escalationDelegation,
    action: "records:read",
    resourceId: RESOURCE,
    actionContext: {},
    policy: escalationPolicyInput,
    issueReceipt: false,
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

  const delegationScopeClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      delegation: { ...staticDelegation, capabilities: ["records:write"] },
    }, 201)),
  });
  await expectInvalidResponse(() => delegationScopeClient.issueDelegation({
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

  const stepUpClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      decisionLogId: "decision-log:other",
      request: staticStepUpRequest,
    }, 201)),
  });
  await expectInvalidResponse(() => stepUpClient.createStepUpRequest({
    decisionLogId: "decision-log:static",
    expiresAt: ARTIFACT_EXPIRY,
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

  const rejectAcceptedClient = new ZkycReferenceClient({
    baseUrl: "https://invalid.reference",
    fetch: () => Promise.resolve(jsonResponse({ ok: true, authorization: staticAuthorization })),
  });
  await expectInvalidResponse(() => rejectAcceptedClient.resolveStepUpRequest(staticAuthorization.requestId, {
    resolution: "REJECT",
    approver: human,
    approverCredential: staticCredential,
  }));
});

test("SDK accepts only exact credentialless direct denial and step-up response envelopes", async () => {
  const { actingCredentialId: _acting, effectiveScopeHash: _scope, credentialId: _credential, ...unboundBase } =
    staticDecision;
  const unboundDenial = {
    ...unboundBase,
    outcome: "DENY",
    reasonCode: "CREDENTIAL_MISSING",
  } as const;
  const credentiallessInput = {
    authorityMode: "DIRECT",
    principal: human,
    credential: null,
    action: staticDecision.action,
    resourceId: staticDecision.resourceId,
    actionContext: {},
    policy: staticPolicyInput,
    issueReceipt: false,
  } as const;

  const denialClient = new ZkycReferenceClient({
    baseUrl: "https://valid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      logId: "decision-log:credentialless",
      decision: unboundDenial,
    })),
  });
  assert.equal((await denialClient.evaluate(credentiallessInput)).decision.reasonCode, "CREDENTIAL_MISSING");

  for (const invalidDecision of [
    { ...unboundDenial, outcome: "ALLOW", reasonCode: "POLICY_ALLOW" },
    {
      ...unboundDenial,
      outcome: "STEP_UP",
      reasonCode: "HUMAN_APPROVAL_REQUIRED",
      requiredApproverCapability: "approval:records-export",
    },
    { ...unboundDenial, reasonCode: "POLICY_DENY" },
    { ...unboundDenial, reasonCode: "CREDENTIAL_MALFORMED" },
    { ...unboundDenial, reasonCode: "CREDENTIAL_UNKNOWN" },
    { ...unboundDenial, actingCredentialId: staticCredential.id },
    { ...unboundDenial, effectiveScopeHash: staticCredential.scopeHash },
    { ...unboundDenial, credentialId: staticCredential.id },
    staticDecision,
    { ...staticDecision, outcome: "DENY", reasonCode: "CREDENTIAL_MISSING" },
  ]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse({
        logId: "decision-log:invalid-credentialless",
        decision: invalidDecision,
      })),
    });
    await expectInvalidResponse(() => client.evaluate(credentiallessInput));
  }

  const validStepUpClient = new ZkycReferenceClient({
    baseUrl: "https://valid.reference",
    fetch: () => Promise.resolve(jsonResponse({
      decisionLogId: "decision-log:static",
      request: staticStepUpRequest,
    }, 201)),
  });
  assert.equal((await validStepUpClient.createStepUpRequest({
    decisionLogId: "decision-log:static",
    expiresAt: ARTIFACT_EXPIRY,
  })).decisionLogId, "decision-log:static");

  for (const malformed of [
    { request: staticStepUpRequest },
    { decisionLogId: "decision-log:static" },
    { decisionLogId: "decision-log:static", request: staticStepUpRequest, unexpected: true },
    {
      decisionLogId: "decision-log:static",
      request: { ...staticStepUpRequest, expiresAt: EXPIRY },
    },
    {
      decisionLogId: "decision-log:static",
      request: { ...staticStepUpRequest, status: "APPROVED" },
    },
  ]) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://invalid.reference",
      fetch: () => Promise.resolve(jsonResponse(malformed, 201)),
    });
    await expectInvalidResponse(() => client.createStepUpRequest({
      decisionLogId: "decision-log:static",
      expiresAt: ARTIFACT_EXPIRY,
    }));
  }
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
    {
      ...staticDecision,
      outcome: "DENY",
      reasonCode: "CREDENTIAL_REVOKED",
      unverifiedMetadata: { zkPassProofId: "proof:must-not-be-accepted" },
    },
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
