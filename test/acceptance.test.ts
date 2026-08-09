import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ActionSensitivity,
  CredentialAuthority,
  DomainValidationError,
  HumanStepUpService,
  InMemoryAtomicNonceStore,
  canonicalJson,
  createPolicy,
  createPrincipal,
  evaluateAccess,
  sha256Version,
  signReceipt,
  verifyAndConsumeReceipt,
  verifyReceipt,
  type AccessDecision,
  type Credential,
  type PermissionRule,
  type Principal,
  type ReceiptExpectedBinding,
  type ReceiptPayload,
} from "../src/index.js";

const ISSUED_AT = "2026-06-01T00:00:00.000Z";
const DECIDED_AT = "2026-06-01T00:10:00.000Z";
const APPROVED_AT = "2026-06-01T00:11:00.000Z";
const EXPIRES_AT = "2026-06-01T01:00:00.000Z";
const RECEIPT_EXPIRES_AT = "2026-06-01T00:20:00.000Z";
const KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const WRONG_KEY = Buffer.from("abcdef0123456789abcdef0123456789", "utf8");
const MEMBER_AFFILIATION = Object.freeze({ organizationId: "organization:ordin", role: "member" });
const REVIEWER_AFFILIATION = Object.freeze({ organizationId: "organization:ordin", role: "reviewer" });

interface HarnessOptions {
  principal?: Principal;
  credentialCapabilities?: readonly string[];
  credentialExpiresAt?: string;
  metadata?: { readonly zkPassProofId?: string; readonly contextualProofIds?: readonly string[] };
  rules?: readonly {
    readonly action: string;
    readonly actionSensitivity: ActionSensitivity;
    readonly requiredCapabilities: readonly string[];
    readonly requiredAffiliations: readonly { readonly organizationId: string; readonly role: string }[];
    readonly effect: "ALLOW" | "DENY" | "STEP_UP";
    readonly approverCapability?: string;
  }[];
}

function createHarness(options: HarnessOptions = {}) {
  const authority = new CredentialAuthority({ issuerId: "issuer:ordin" });
  const principal = options.principal ?? createPrincipal({
    id: "principal:alice",
    affiliations: [MEMBER_AFFILIATION],
  });
  const credential = authority.issueCredential({
    id: "credential:alice",
    principal,
    capabilities: options.credentialCapabilities ?? ["records:read", "records:export"],
    issuedAt: ISSUED_AT,
    expiresAt: options.credentialExpiresAt ?? EXPIRES_AT,
    ...(options.metadata === undefined ? {} : { unverifiedMetadata: options.metadata }),
  });
  const policy = createPolicy({
    id: "policy:ordin-reference",
    rules: options.rules ?? [
      {
        action: "records:read",
        actionSensitivity: ActionSensitivity.ROUTINE,
        requiredCapabilities: ["records:read"],
        requiredAffiliations: [MEMBER_AFFILIATION],
        effect: "ALLOW",
      },
      {
        action: "records:delete",
        actionSensitivity: ActionSensitivity.CRITICAL,
        requiredCapabilities: ["records:delete"],
        requiredAffiliations: [MEMBER_AFFILIATION],
        effect: "DENY",
      },
      {
        action: "records:export",
        actionSensitivity: ActionSensitivity.SENSITIVE,
        requiredCapabilities: ["records:export"],
        requiredAffiliations: [MEMBER_AFFILIATION],
        effect: "STEP_UP",
        approverCapability: "approval:records-export",
      },
    ],
  });
  return { authority, principal, credential, policy };
}

function evaluate(
  harness: ReturnType<typeof createHarness>,
  input: {
    credential?: Credential | null;
    principal?: Principal;
    action?: string;
    resourceId?: string;
    actionContext?: Readonly<Record<string, unknown>>;
    at?: string;
  } = {},
): AccessDecision {
  return evaluateAccess({
    principal: input.principal ?? harness.principal,
    credential: input.credential === undefined ? harness.credential : input.credential,
    action: input.action ?? "records:read",
    resourceId: input.resourceId ?? "record:customer-7",
    actionContext: input.actionContext ?? { purpose: "review", fields: ["name", "status"] },
    policy: harness.policy,
    at: input.at ?? DECIDED_AT,
    credentialAuthority: harness.authority,
  });
}

function receiptPayload(
  decision: AccessDecision,
  input: { nonce?: string; decision?: ReceiptPayload["decision"]; reasonCode?: ReceiptPayload["reasonCode"] } = {},
): ReceiptPayload {
  if (decision.credentialId === undefined) throw new Error("decision must bind a credential");
  return {
    version: 1,
    subjectId: decision.subjectId,
    action: decision.action,
    actionSensitivity: decision.actionSensitivity,
    resourceId: decision.resourceId,
    contextHash: decision.contextHash,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    credentialId: decision.credentialId,
    decision: input.decision ?? decision.outcome,
    reasonCode: input.reasonCode ?? decision.reasonCode,
    nonce: input.nonce ?? "nonce:receipt-1",
    decidedAt: decision.decidedAt,
    issuedAt: decision.decidedAt,
    expiresAt: RECEIPT_EXPIRES_AT,
  };
}

function expectedReceiptBinding(decision: AccessDecision) {
  if (decision.credentialId === undefined) throw new Error("decision must bind a credential");
  return {
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
  };
}

function createApprover(authority: CredentialAuthority, capabilities = ["approval:records-export"]) {
  const principal = createPrincipal({
    id: "principal:bob",
    affiliations: [REVIEWER_AFFILIATION],
  });
  const credential = authority.issueCredential({
    id: "credential:bob",
    principal,
    capabilities,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  return { principal, credential };
}

test("1 deterministic ALLOW binds credential affiliations, sensitivity, resource, context and policy", () => {
  const harness = createHarness();
  const first = evaluate(harness);
  const second = evaluate(harness, {
    actionContext: { fields: ["name", "status"], purpose: "review" },
  });
  assert.deepEqual(first, second);
  assert.equal(first.outcome, "ALLOW");
  assert.equal(first.reasonCode, "POLICY_ALLOW");
  assert.equal(first.actionSensitivity, ActionSensitivity.ROUTINE);
  assert.equal(first.resourceId, "record:customer-7");
  assert.match(first.contextHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.credentialId, harness.credential.id);
});

test("2 required affiliation is enforced and caller-injected affiliation cannot elevate", () => {
  const missingHarness = createHarness({
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [REVIEWER_AFFILIATION],
      effect: "ALLOW",
    }],
  });
  assert.equal(evaluate(missingHarness).reasonCode, "AFFILIATION_REQUIRED");

  const injectedPrincipal = createPrincipal({
    id: missingHarness.principal.id,
    affiliations: [MEMBER_AFFILIATION, REVIEWER_AFFILIATION],
  });
  const injected = evaluate(missingHarness, { principal: injectedPrincipal });
  assert.equal(injected.outcome, "DENY");
  assert.equal(injected.reasonCode, "CREDENTIAL_SUBJECT_MISMATCH");
});

test("3 matching credential-bound affiliation permits evaluation", () => {
  const reviewer = createPrincipal({ id: "principal:reviewer", affiliations: [REVIEWER_AFFILIATION] });
  const harness = createHarness({
    principal: reviewer,
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [REVIEWER_AFFILIATION],
      effect: "ALLOW",
    }],
  });
  assert.equal(evaluate(harness).outcome, "ALLOW");
});

test("4 missing, malformed, expired and revoked credentials fail closed", () => {
  const harness = createHarness();
  assert.equal(evaluate(harness, { credential: null }).reasonCode, "CREDENTIAL_MISSING");
  assert.equal(
    evaluateAccess({
      principal: harness.principal,
      credential: "not-a-credential",
      action: "records:read",
      resourceId: "record:customer-7",
      actionContext: {},
      policy: harness.policy,
      at: DECIDED_AT,
      credentialAuthority: harness.authority,
    }).reasonCode,
    "CREDENTIAL_MALFORMED",
  );

  const expired = createHarness({ credentialExpiresAt: "2026-06-01T00:05:00.000Z" });
  assert.equal(evaluate(expired).reasonCode, "CREDENTIAL_EXPIRED");

  assert.equal(
    evaluate(harness, { at: "2026-05-31T23:59:59.000Z" }).reasonCode,
    "CREDENTIAL_NOT_YET_VALID",
  );
  const unknownCredential = {
    ...harness.credential,
    id: "credential:unknown",
  } as Credential;
  assert.equal(evaluate(harness, { credential: unknownCredential }).reasonCode, "CREDENTIAL_UNKNOWN");

  assert.equal(
    harness.authority.revokeCredential(harness.credential.id, {
      revokedAt: "2026-06-01T00:09:00.000Z",
      reason: "security-review",
    }),
    true,
  );
  assert.equal(evaluate(harness).reasonCode, "CREDENTIAL_REVOKED");
});

test("5 explicit DENY, insufficient capability and unknown action return stable reasons", () => {
  const harness = createHarness();
  assert.equal(evaluate(harness, { action: "records:delete" }).reasonCode, "POLICY_DENY");
  const limited = createHarness({ credentialCapabilities: [] });
  assert.equal(evaluate(limited).reasonCode, "INSUFFICIENT_CAPABILITY");
  assert.equal(evaluate(harness, { action: "records:publish" }).reasonCode, "ACTION_NOT_PERMITTED");
});

test("6 malformed and contradictory policy/input is rejected or denied", () => {
  assert.throws(
    () => createPolicy({
      id: "policy:duplicate",
      rules: [
        {
          action: "records:read",
          actionSensitivity: ActionSensitivity.ROUTINE,
          requiredCapabilities: [],
          requiredAffiliations: [],
          effect: "ALLOW",
        },
        {
          action: "records:read",
          actionSensitivity: ActionSensitivity.CRITICAL,
          requiredCapabilities: [],
          requiredAffiliations: [],
          effect: "DENY",
        },
      ],
    }),
    DomainValidationError,
  );
  const harness = createHarness();
  const invalid = evaluateAccess({
    principal: harness.principal,
    credential: harness.credential,
    action: "records:read",
    resourceId: "record:customer-7",
    actionContext: {},
    policy: harness.policy,
    at: DECIDED_AT,
    credentialAuthority: harness.authority,
    unsupported: true,
  });
  assert.equal(invalid.outcome, "DENY");
  assert.equal(invalid.reasonCode, "INVALID_INPUT");
  const stalePolicy = { ...harness.policy, version: `sha256:${"0".repeat(64)}` };
  const stale = evaluateAccess({
    principal: harness.principal,
    credential: harness.credential,
    action: "records:read",
    resourceId: "record:customer-7",
    actionContext: {},
    policy: stalePolicy,
    at: DECIDED_AT,
    credentialAuthority: harness.authority,
  });
  assert.equal(stale.outcome, "DENY");
  assert.equal(stale.reasonCode, "INVALID_INPUT");
});

test("7 human step-up approval is bound and consumable exactly once", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export", resourceId: "dataset:7" });
  assert.equal(decision.outcome, "STEP_UP");
  const store = new InMemoryAtomicNonceStore();
  const service = new HumanStepUpService({ credentialAuthority: harness.authority, nonceStore: store });
  const request = service.createRequest({
    id: "step-up:export-7",
    decision,
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  assert.equal(request.actionSensitivity, ActionSensitivity.SENSITIVE);
  const approver = createApprover(harness.authority);
  const resolved = await service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: approver.principal,
    approverCredential: approver.credential,
    at: APPROVED_AT,
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) return;
  const consumeInput = {
    authorization: resolved.authorization,
    subjectId: decision.subjectId,
    action: decision.action,
    actionSensitivity: decision.actionSensitivity,
    resourceId: decision.resourceId,
    contextHash: decision.contextHash,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    credentialId: decision.credentialId as string,
    at: "2026-06-01T00:12:00.000Z",
  };
  assert.equal(await service.consumeAuthorization(consumeInput), true);
  assert.equal(await service.consumeAuthorization(consumeInput), false);
});

test("8 step-up redirect attempts fail for resource, context, policy and sensitivity", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export", resourceId: "dataset:7" });
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const request = service.createRequest({ id: "step-up:redirect", decision, expiresAt: RECEIPT_EXPIRES_AT });
  const approver = createApprover(harness.authority);
  const resolved = await service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: approver.principal,
    approverCredential: approver.credential,
    at: APPROVED_AT,
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) return;
  const base = {
    authorization: resolved.authorization,
    subjectId: decision.subjectId,
    action: decision.action,
    actionSensitivity: decision.actionSensitivity,
    resourceId: decision.resourceId,
    contextHash: decision.contextHash,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    credentialId: decision.credentialId as string,
    at: "2026-06-01T00:12:00.000Z",
  };
  assert.equal(await service.consumeAuthorization({ ...base, resourceId: "dataset:8" }), false);
  assert.equal(await service.consumeAuthorization({ ...base, contextHash: `sha256:${"0".repeat(64)}` }), false);
  assert.equal(await service.consumeAuthorization({ ...base, policyId: "policy:other" }), false);
  assert.equal(await service.consumeAuthorization({ ...base, actionSensitivity: ActionSensitivity.CRITICAL }), false);
  assert.equal(await service.consumeAuthorization(base), true);
});

test("9 unauthorized, rejected and expired step-up paths fail closed", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export" });
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const unauthorizedRequest = service.createRequest({
    id: "step-up:unauthorized",
    decision,
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  const unauthorized = createApprover(harness.authority, ["approval:other"]);
  assert.deepEqual(
    await service.resolveRequest({
      requestId: unauthorizedRequest.id,
      resolution: "APPROVE",
      approver: unauthorized.principal,
      approverCredential: unauthorized.credential,
      at: APPROVED_AT,
    }),
    { ok: false, reasonCode: "APPROVER_CAPABILITY_MISSING" },
  );

  const authorized = createPrincipal({ id: "principal:carol", affiliations: [REVIEWER_AFFILIATION] });
  const authorizedCredential = harness.authority.issueCredential({
    id: "credential:carol",
    principal: authorized,
    capabilities: ["approval:records-export"],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  const timeTravelRequest = service.createRequest({
    id: "step-up:time-travel",
    decision,
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  assert.deepEqual(
    await service.resolveRequest({
      requestId: timeTravelRequest.id,
      resolution: "APPROVE",
      approver: authorized,
      approverCredential: authorizedCredential,
      at: "2026-06-01T00:09:59.000Z",
    }),
    { ok: false, reasonCode: "INVALID_INPUT" },
  );
  assert.deepEqual(
    await service.resolveRequest({
      requestId: unauthorizedRequest.id,
      resolution: "REJECT",
      approver: authorized,
      approverCredential: authorizedCredential,
      at: APPROVED_AT,
    }),
    { ok: false, reasonCode: "STEP_UP_REJECTED" },
  );

  const expiredRequest = service.createRequest({
    id: "step-up:expired",
    decision,
    expiresAt: "2026-06-01T00:11:00.000Z",
  });
  assert.deepEqual(
    await service.resolveRequest({
      requestId: expiredRequest.id,
      resolution: "APPROVE",
      approver: authorized,
      approverCredential: authorizedCredential,
      at: "2026-06-01T00:11:00.000Z",
    }),
    { ok: false, reasonCode: "STEP_UP_EXPIRED" },
  );
});

test("10 concurrent approve/reject has exactly one terminal transition", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export" });
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const request = service.createRequest({ id: "step-up:race", decision, expiresAt: RECEIPT_EXPIRES_AT });
  const approver = createApprover(harness.authority);
  const results = await Promise.all([
    service.resolveRequest({
      requestId: request.id,
      resolution: "APPROVE",
      approver: approver.principal,
      approverCredential: approver.credential,
      at: APPROVED_AT,
    }),
    service.resolveRequest({
      requestId: request.id,
      resolution: "REJECT",
      approver: approver.principal,
      approverCredential: approver.credential,
      at: APPROVED_AT,
    }),
  ]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(results.filter((result) => !result.ok && result.reasonCode === "STEP_UP_ALREADY_RESOLVED").length, 1);
  assert.equal(service.getRequest(request.id)?.status, "APPROVED");
});

test("11 credential revocation after approval invalidates step-up consumption", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export" });
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const request = service.createRequest({ id: "step-up:revoked", decision, expiresAt: RECEIPT_EXPIRES_AT });
  const approver = createApprover(harness.authority);
  const resolved = await service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: approver.principal,
    approverCredential: approver.credential,
    at: APPROVED_AT,
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) return;
  harness.authority.revokeCredential(harness.credential.id, {
    revokedAt: "2026-06-01T00:11:30.000Z",
    reason: "subject-revoked",
  });
  assert.equal(
    await service.consumeAuthorization({
      authorization: resolved.authorization,
      subjectId: decision.subjectId,
      action: decision.action,
      actionSensitivity: decision.actionSensitivity,
      resourceId: decision.resourceId,
      contextHash: decision.contextHash,
      policyId: decision.policyId,
      policyVersion: decision.policyVersion,
      credentialId: decision.credentialId as string,
      at: "2026-06-01T00:12:00.000Z",
    }),
    false,
  );
});

test("12 receipt signing and verification detect wrong key, tampering and expiry", () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY);
  assert.deepEqual(
    verifyReceipt(receipt, KEY, { at: DECIDED_AT, expected: expectedReceiptBinding(decision) }),
    { valid: true, reasonCode: "RECEIPT_VALID" },
  );
  assert.equal(verifyReceipt(receipt, WRONG_KEY, { at: DECIDED_AT }).reasonCode, "RECEIPT_SIGNATURE_INVALID");
  assert.equal(
    verifyReceipt(receipt, KEY, { at: "2026-06-01T00:09:59.000Z" }).reasonCode,
    "RECEIPT_NOT_YET_VALID",
  );
  assert.throws(() => signReceipt(receiptPayload(decision), Buffer.alloc(31)), DomainValidationError);
  const tampered = {
    ...receipt,
    payload: { ...receipt.payload, resourceId: "record:customer-8" },
  };
  assert.equal(verifyReceipt(tampered, KEY, { at: DECIDED_AT }).reasonCode, "RECEIPT_SIGNATURE_INVALID");
  assert.equal(
    verifyReceipt(receipt, KEY, { at: RECEIPT_EXPIRES_AT }).reasonCode,
    "RECEIPT_EXPIRED",
  );
});

test("13 receipt consumption requires complete bindings and rejects every redirect field", async () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY);
  const expected = expectedReceiptBinding(decision);
  const redirects: readonly ReceiptExpectedBinding[] = [
    { ...expected, subjectId: "principal:mallory" },
    { ...expected, action: "records:write" },
    { ...expected, actionSensitivity: ActionSensitivity.CRITICAL },
    { ...expected, resourceId: "record:customer-8" },
    { ...expected, contextHash: `sha256:${"0".repeat(64)}` },
    { ...expected, policyId: "policy:other" },
    { ...expected, policyVersion: `sha256:${"1".repeat(64)}` },
    { ...expected, credentialId: "credential:other" },
    { ...expected, decision: "DENY" },
    { ...expected, reasonCode: "POLICY_DENY" },
  ];
  const store = new InMemoryAtomicNonceStore();
  for (const redirected of redirects) {
    assert.deepEqual(
      await verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, {
        at: DECIDED_AT,
        expected: redirected,
      }),
      { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" },
    );
  }
  assert.deepEqual(
    await verifyAndConsumeReceipt(
      receipt,
      KEY,
      store,
      harness.authority,
      { at: DECIDED_AT } as { at: string; expected: ReceiptExpectedBinding },
    ),
    { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" },
  );
  const inheritedExpected = Object.create(expected) as ReceiptExpectedBinding;
  Object.defineProperty(inheritedExpected, "resourceId", {
    value: "record:customer-8",
    enumerable: false,
  });
  assert.deepEqual(
    await verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, {
      at: DECIDED_AT,
      expected: inheritedExpected,
    }),
    { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" },
  );
  assert.equal(
    (await verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, {
      at: DECIDED_AT,
      expected,
    })).valid,
    true,
  );
});

test("14 contradictory receipt decision/reason combinations are rejected", () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  assert.throws(
    () => signReceipt(receiptPayload(decision, { decision: "ALLOW", reasonCode: "POLICY_DENY" }), KEY),
    DomainValidationError,
  );
  assert.throws(
    () => signReceipt(receiptPayload(decision, { decision: "STEP_UP", reasonCode: "POLICY_ALLOW" }), KEY),
    DomainValidationError,
  );
  assert.throws(
    () => signReceipt(receiptPayload(decision, { decision: "DENY", reasonCode: "POLICY_ALLOW" }), KEY),
    DomainValidationError,
  );
});

test("15 non-authorizing DENY and STEP_UP receipts are never consumed", async () => {
  const harness = createHarness();
  const deny = evaluate(harness, { action: "records:delete" });
  const denyReceipt = signReceipt(receiptPayload(deny), KEY);
  const store = new InMemoryAtomicNonceStore();
  assert.deepEqual(
    await verifyAndConsumeReceipt(denyReceipt, KEY, store, harness.authority, {
      at: DECIDED_AT,
      expected: expectedReceiptBinding(deny),
    }),
    { valid: false, reasonCode: "RECEIPT_NOT_AUTHORIZING" },
  );
  const stepUp = evaluate(harness, { action: "records:export" });
  const stepUpReceipt = signReceipt(receiptPayload(stepUp, { nonce: "nonce:step-up" }), KEY);
  assert.deepEqual(
    await verifyAndConsumeReceipt(stepUpReceipt, KEY, store, harness.authority, {
      at: DECIDED_AT,
      expected: expectedReceiptBinding(stepUp),
    }),
    { valid: false, reasonCode: "RECEIPT_NOT_AUTHORIZING" },
  );
});

test("16 credential revocation after receipt signing invalidates consumption", async () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY);
  harness.authority.revokeCredential(harness.credential.id, {
    revokedAt: "2026-06-01T00:11:00.000Z",
    reason: "post-signing-revocation",
  });
  assert.deepEqual(
    await verifyAndConsumeReceipt(
      receipt,
      KEY,
      new InMemoryAtomicNonceStore(),
      harness.authority,
      { at: "2026-06-01T00:12:00.000Z", expected: expectedReceiptBinding(decision) },
    ),
    { valid: false, reasonCode: "RECEIPT_CREDENTIAL_INVALID" },
  );
});

test("17 receipt replay is rejected sequentially", async () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY);
  const store = new InMemoryAtomicNonceStore();
  const options = { at: DECIDED_AT, expected: expectedReceiptBinding(decision) };
  assert.equal((await verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, options)).valid, true);
  assert.deepEqual(
    await verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, options),
    { valid: false, reasonCode: "RECEIPT_REPLAYED" },
  );
  const maximumLengthNonceReceipt = signReceipt(
    receiptPayload(decision, { nonce: "n".repeat(128) }),
    KEY,
  );
  assert.equal(
    (await verifyAndConsumeReceipt(
      maximumLengthNonceReceipt,
      KEY,
      new InMemoryAtomicNonceStore(),
      harness.authority,
      options,
    )).valid,
    true,
  );
});

test("18 concurrent replay attempts yield exactly one authorization", async () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY);
  const store = new InMemoryAtomicNonceStore();
  const attempts = await Promise.all(
    Array.from({ length: 32 }, () =>
      verifyAndConsumeReceipt(receipt, KEY, store, harness.authority, {
        at: DECIDED_AT,
        expected: expectedReceiptBinding(decision),
      }),
    ),
  );
  assert.equal(attempts.filter((attempt) => attempt.valid).length, 1);
  assert.equal(attempts.filter((attempt) => attempt.reasonCode === "RECEIPT_REPLAYED").length, 31);
});

test("19 zkPassProofId remains unverified metadata and does not affect authority", () => {
  const harness = createHarness({ metadata: { zkPassProofId: "zkpass:context-only" } });
  const decision = evaluate(harness);
  assert.equal(decision.outcome, "ALLOW");
  assert.equal(decision.unverifiedMetadata?.zkPassProofId, "zkpass:context-only");
  assert.throws(
    () => harness.authority.issueCredential({
      id: "credential:bad-metadata",
      principal: harness.principal,
      capabilities: ["records:read"],
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      unverifiedMetadata: { verified: true } as never,
    }),
    DomainValidationError,
  );
});

test("20 policy version is content-derived and deterministic", () => {
  const harness = createHarness();
  const same = createPolicy({ id: harness.policy.id, rules: [...harness.policy.rules].reverse() });
  assert.equal(same.version, harness.policy.version);
  const changed = createPolicy({
    id: harness.policy.id,
    rules: harness.policy.rules.map((rule: PermissionRule) =>
      rule.action === "records:read"
        ? { ...rule, actionSensitivity: ActionSensitivity.SENSITIVE }
        : rule,
    ),
  });
  assert.notEqual(changed.version, harness.policy.version);
});

interface FixtureCase {
  readonly name: string;
  readonly principal: unknown;
  readonly credential: {
    readonly id: string;
    readonly capabilities: readonly string[];
    readonly issuedAt: string;
    readonly expiresAt: string;
    readonly unverifiedMetadata?: { readonly zkPassProofId?: string };
  };
  readonly action: string;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: unknown;
  readonly at: string;
  readonly expected: { readonly outcome: string; readonly reasonCode: string };
}

test("21 checked-in fixtures execute through the public API", async () => {
  const url = new URL("../../fixtures/public-api-cases.json", import.meta.url);
  const fixtures = JSON.parse(await readFile(url, "utf8")) as FixtureCase[];
  for (const fixture of fixtures) {
    const authority = new CredentialAuthority({ issuerId: `issuer:${fixture.name}` });
    const principal = createPrincipal(fixture.principal);
    const credential = authority.issueCredential({
      id: fixture.credential.id,
      principal,
      capabilities: fixture.credential.capabilities,
      issuedAt: fixture.credential.issuedAt,
      expiresAt: fixture.credential.expiresAt,
      ...(fixture.credential.unverifiedMetadata === undefined
        ? {}
        : { unverifiedMetadata: fixture.credential.unverifiedMetadata }),
    });
    const policy = createPolicy(fixture.policy);
    const decision = evaluateAccess({
      principal,
      credential,
      action: fixture.action,
      resourceId: fixture.resourceId,
      actionContext: fixture.actionContext,
      policy,
      at: fixture.at,
      credentialAuthority: authority,
    });
    assert.equal(decision.outcome, fixture.expected.outcome, fixture.name);
    assert.equal(decision.reasonCode, fixture.expected.reasonCode, fixture.name);
  }
});

test("22 canonical JSON preserves __proto__ as data and prevents context-hash collision", () => {
  const withProtoKey = JSON.parse('{"__proto__":{"admin":true}}') as Record<string, unknown>;
  assert.equal(canonicalJson(withProtoKey), '{"__proto__":{"admin":true}}');
  assert.notEqual(sha256Version(withProtoKey), sha256Version({}));
});
