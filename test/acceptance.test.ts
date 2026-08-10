import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ActionSensitivity,
  CredentialAuthority,
  DelegationAuthority,
  DelegationValidationError,
  DomainValidationError,
  HumanStepUpService,
  InMemoryAtomicNonceStore,
  PolicyRegistry,
  PrincipalType,
  canonicalJson,
  computeDelegationBindingHash,
  computeScopeHash,
  createPolicy,
  createPrincipal,
  evaluateAccess,
  sha256Version,
  signReceipt,
  verifyAndConsumeReceipt,
  verifyReceipt,
  type AccessDecision,
  type CapabilityDelegation,
  type Credential,
  type PermissionRule,
  type Policy,
  type Principal,
  type ReceiptExpectedBinding,
  type ReceiptPayload,
  type StepUpAuthorization,
  type StepUpAuthorizationBinding,
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
  credentialAllowedActions?: readonly string[];
  credentialAllowedResourceIds?: readonly string[];
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
  const principal = options.principal ?? createPrincipal({
    id: "principal:alice",
    type: PrincipalType.HUMAN,
    affiliations: [MEMBER_AFFILIATION],
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
  const policyRegistry = new PolicyRegistry({ policies: [policy] });
  const authority = new CredentialAuthority({ issuerId: "issuer:ordin", policyRegistry });
  const credential = authority.issueCredential({
    id: "credential:alice",
    principal,
    capabilities: options.credentialCapabilities ?? ["records:read", "records:export"],
    allowedActions: options.credentialAllowedActions ?? [
      "records:delete",
      "records:export",
      "records:publish",
      "records:read",
    ],
    allowedResourceIds: options.credentialAllowedResourceIds ?? [
      "dataset:7",
      "record:customer-7",
    ],
    issuedAt: ISSUED_AT,
    expiresAt: options.credentialExpiresAt ?? EXPIRES_AT,
    ...(options.metadata === undefined ? {} : { unverifiedMetadata: options.metadata }),
  });
  return { authority, policyRegistry, principal, credential, policy };
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
    authorityMode: "DIRECT",
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
  input: {
    nonce?: string;
    decision?: ReceiptPayload["decision"];
    reasonCode?: ReceiptPayload["reasonCode"];
    issuedAt?: string;
    expiresAt?: string;
  } = {},
): ReceiptPayload {
  if (
    decision.authorityMode === undefined ||
    decision.subjectType === undefined ||
    decision.actingCredentialId === undefined ||
    decision.effectiveScopeHash === undefined
  ) {
    throw new Error("decision must bind complete receipt authority");
  }
  const outcome = input.decision ?? decision.outcome;
  const common = {
    version: 2 as const,
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
    decision: outcome,
    reasonCode: input.reasonCode ?? decision.reasonCode,
    ...(outcome === "STEP_UP"
      ? { requiredApproverCapability: decision.requiredApproverCapability as string }
      : {}),
    nonce: input.nonce ?? "nonce:receipt-1",
    decidedAt: decision.decidedAt,
    issuedAt: input.issuedAt ?? decision.decidedAt,
    expiresAt: input.expiresAt ?? RECEIPT_EXPIRES_AT,
  };
  if (decision.authorityMode === "DIRECT") {
    return {
      ...common,
      authorityMode: "DIRECT",
      ...(decision.credentialId === undefined ? {} : { credentialId: decision.credentialId }),
    };
  }
  if (
    decision.grantorId === undefined ||
    decision.grantorType === undefined ||
    decision.grantorCredentialId === undefined ||
    decision.delegationId === undefined ||
    decision.delegationBindingHash === undefined
  ) {
    throw new Error("delegated decision must bind complete delegated authority");
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

function expectedReceiptBinding(decision: AccessDecision): ReceiptExpectedBinding {
  const payload = receiptPayload(decision);
  const {
    version: _version,
    nonce: _nonce,
    decidedAt: _decidedAt,
    issuedAt: _issuedAt,
    expiresAt: _expiresAt,
    ...binding
  } = payload;
  return binding;
}

function createApprover(
  authority: CredentialAuthority,
  capabilities = ["approval:records-export"],
  input: {
    readonly id?: string;
    readonly type?: PrincipalType;
    readonly allowedActions?: readonly string[];
    readonly allowedResourceIds?: readonly string[];
    readonly expiresAt?: string;
  } = {},
) {
  const id = input.id ?? "bob";
  const principal = createPrincipal({
    id: `principal:${id}`,
    type: input.type ?? PrincipalType.HUMAN,
    affiliations: [REVIEWER_AFFILIATION],
  });
  const credential = authority.issueCredential({
    id: `credential:${id}`,
    principal,
    capabilities,
    allowedActions: input.allowedActions ?? ["step-up:resolve"],
    allowedResourceIds: input.allowedResourceIds ?? [
      "dataset:7",
      "record:1",
      "record:customer-7",
    ],
    issuedAt: ISSUED_AT,
    expiresAt: input.expiresAt ?? EXPIRES_AT,
  });
  return { principal, credential };
}

function stepUpBinding(authorization: StepUpAuthorization): StepUpAuthorizationBinding {
  const common = {
    requestId: authorization.requestId,
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
  return authorization.authorityMode === "DIRECT"
    ? {
      ...common,
      authorityMode: "DIRECT",
      ...(authorization.credentialId === undefined
        ? {}
        : { credentialId: authorization.credentialId }),
    }
    : {
      ...common,
      authorityMode: "DELEGATED",
      grantorId: authorization.grantorId,
      grantorType: authorization.grantorType,
      grantorCredentialId: authorization.grantorCredentialId,
      delegationId: authorization.delegationId,
      delegationBindingHash: authorization.delegationBindingHash,
    };
}

function createDelegationHarness(input: {
  readonly delegationIssuedAt?: string;
  readonly delegationExpiresAt?: string;
  readonly policy?: Policy;
  readonly additionalTrustedPolicies?: readonly Policy[];
  readonly delegate?: Principal;
  readonly grantorCapabilities?: readonly string[];
  readonly grantorAllowedActions?: readonly string[];
  readonly grantorAllowedResourceIds?: readonly string[];
  readonly delegatedCapabilities?: readonly string[];
  readonly delegatedAllowedActions?: readonly string[];
  readonly delegatedAllowedResourceIds?: readonly string[];
} = {}) {
  const policy = input.policy ?? createPolicy({
    id: "policy:delegated-reference",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  });
  const policyRegistry = new PolicyRegistry({
    policies: [policy, ...(input.additionalTrustedPolicies ?? [])],
  });
  const credentialAuthority = new CredentialAuthority({ issuerId: "issuer:ordin", policyRegistry });
  const grantor = createPrincipal({
    id: "principal:grantor",
    type: PrincipalType.ORGANIZATION,
    affiliations: [MEMBER_AFFILIATION],
  });
  const delegate = input.delegate ?? createPrincipal({
    id: "principal:delegate-agent",
    type: PrincipalType.AGENT,
    affiliations: [],
  });
  const grantorCredential = credentialAuthority.issueCredential({
    id: "credential:grantor",
    principal: grantor,
    capabilities: input.grantorCapabilities ?? ["records:write", "records:read"],
    allowedActions: input.grantorAllowedActions ?? ["records:write", "records:read"],
    allowedResourceIds: input.grantorAllowedResourceIds ?? ["record:2", "record:1"],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  const delegateIdentityCredential = credentialAuthority.issueCredential({
    id: "credential:delegate-identity",
    principal: delegate,
    capabilities: [],
    allowedActions: [],
    allowedResourceIds: [],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  const delegationAuthority = new DelegationAuthority({
    issuerId: "delegation-issuer:ordin",
    credentialAuthority,
  });
  const delegation = delegationAuthority.issueDelegation({
    id: "delegation:grantor-to-agent",
    grantor,
    grantorCredential,
    delegate,
    policy,
    capabilities: input.delegatedCapabilities ?? ["records:read"],
    allowedActions: input.delegatedAllowedActions ?? ["records:read"],
    allowedResourceIds: input.delegatedAllowedResourceIds ?? ["record:1"],
    issuedAt: input.delegationIssuedAt ?? ISSUED_AT,
    expiresAt: input.delegationExpiresAt ?? EXPIRES_AT,
  });
  return {
    credentialAuthority,
    policyRegistry,
    grantor,
    delegate,
    grantorCredential,
    delegateIdentityCredential,
    policy,
    delegationAuthority,
    delegation,
  };
}

function evaluateDelegated(
  harness: ReturnType<typeof createDelegationHarness>,
  input: {
    readonly principal?: Principal;
    readonly delegateIdentityCredential?: Credential;
    readonly grantorCredential?: Credential;
    readonly delegation?: CapabilityDelegation;
    readonly policy?: Policy;
    readonly action?: string;
    readonly resourceId?: string;
    readonly actionContext?: Readonly<Record<string, unknown>>;
    readonly at?: string;
  } = {},
): AccessDecision {
  return evaluateAccess({
    authorityMode: "DELEGATED",
    principal: input.principal ?? harness.delegate,
    delegateIdentityCredential:
      input.delegateIdentityCredential ?? harness.delegateIdentityCredential,
    grantorCredential: input.grantorCredential ?? harness.grantorCredential,
    delegation: input.delegation ?? harness.delegation,
    action: input.action ?? "records:read",
    resourceId: input.resourceId ?? "record:1",
    actionContext: input.actionContext ?? { fields: ["name"], purpose: "delegated-review" },
    policy: input.policy ?? harness.policy,
    at: input.at ?? DECIDED_AT,
    credentialAuthority: harness.credentialAuthority,
    delegationAuthority: harness.delegationAuthority,
  });
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
  assert.equal(first.version, 2);
  assert.equal(first.authorityMode, "DIRECT");
  assert.equal(first.subjectType, harness.principal.type);
  assert.equal(first.actingCredentialId, harness.credential.id);
  assert.equal(first.effectiveScopeHash, harness.credential.scopeHash);
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
    type: missingHarness.principal.type,
    affiliations: [MEMBER_AFFILIATION, REVIEWER_AFFILIATION],
  });
  const injected = evaluate(missingHarness, { principal: injectedPrincipal });
  assert.equal(injected.outcome, "DENY");
  assert.equal(injected.reasonCode, "CREDENTIAL_SUBJECT_MISMATCH");
});

test("3 matching credential-bound affiliation permits evaluation", () => {
  const reviewer = createPrincipal({
    id: "principal:reviewer",
    type: PrincipalType.HUMAN,
    affiliations: [REVIEWER_AFFILIATION],
  });
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
      authorityMode: "DIRECT",
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

test("5a direct mode enforces exact principal type and credential action/resource scope", () => {
  const harness = createHarness({
    credentialAllowedActions: ["records:read"],
    credentialAllowedResourceIds: ["record:customer-7"],
  });
  const wrongType = createPrincipal({
    id: harness.principal.id,
    type: PrincipalType.AGENT,
    affiliations: harness.principal.affiliations,
  });
  assert.equal(
    evaluate(harness, { principal: wrongType }).reasonCode,
    "CREDENTIAL_SUBJECT_MISMATCH",
  );
  assert.equal(
    evaluate(harness, { action: "records:export" }).reasonCode,
    "ACTION_OUTSIDE_CREDENTIAL_SCOPE",
  );
  assert.equal(
    evaluate(harness, { resourceId: "dataset:7" }).reasonCode,
    "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE",
  );
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
    authorityMode: "DIRECT",
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
    authorityMode: "DIRECT",
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
    ...stepUpBinding(resolved.authorization),
    at: "2026-06-01T00:12:00.000Z",
  };
  assert.deepEqual(
    service.inspectAuthorization({
      authorization: resolved.authorization,
      at: consumeInput.at,
    }),
    { usable: true, reasonCode: "STEP_UP_AUTHORIZATION_USABLE" },
  );
  assert.equal(await service.consumeAuthorization(consumeInput), true);
  assert.deepEqual(
    service.inspectAuthorization({
      authorization: resolved.authorization,
      at: consumeInput.at,
    }),
    { usable: false, reasonCode: "STEP_UP_AUTHORIZATION_CONSUMED" },
  );
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
    ...stepUpBinding(resolved.authorization),
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

  const authorized = createPrincipal({
    id: "principal:carol",
    type: PrincipalType.HUMAN,
    affiliations: [REVIEWER_AFFILIATION],
  });
  const authorizedCredential = harness.authority.issueCredential({
    id: "credential:carol",
    principal: authorized,
    capabilities: ["approval:records-export"],
    allowedActions: ["step-up:resolve"],
    allowedResourceIds: ["record:customer-7"],
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
      ...stepUpBinding(resolved.authorization),
      at: "2026-06-01T00:12:00.000Z",
    }),
    false,
  );
});

test("12 receipt signing and verification detect wrong key, tampering and expiry", () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(receiptPayload(decision), KEY, harness.authority);
  assert.deepEqual(
    verifyReceipt(receipt, KEY, { at: DECIDED_AT, expected: expectedReceiptBinding(decision) }),
    { valid: true, reasonCode: "RECEIPT_VALID" },
  );
  assert.equal(verifyReceipt(receipt, WRONG_KEY, { at: DECIDED_AT }).reasonCode, "RECEIPT_SIGNATURE_INVALID");
  assert.equal(
    verifyReceipt(receipt, KEY, { at: "2026-06-01T00:09:59.000Z" }).reasonCode,
    "RECEIPT_NOT_YET_VALID",
  );
  assert.throws(
    () => signReceipt(receiptPayload(decision), Buffer.alloc(31), harness.authority),
    DomainValidationError,
  );
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
  const receipt = signReceipt(receiptPayload(decision), KEY, harness.authority);
  const expected = expectedReceiptBinding(decision);
  assert.equal(expected.authorityMode, "DIRECT");
  if (expected.authorityMode !== "DIRECT") return;
  const redirects: readonly ReceiptExpectedBinding[] = [
    { ...expected, authorityMode: "DELEGATED" } as ReceiptExpectedBinding,
    { ...expected, subjectId: "principal:mallory" },
    { ...expected, subjectType: PrincipalType.AGENT },
    { ...expected, actingCredentialId: "credential:other", credentialId: "credential:other" },
    { ...expected, effectiveScopeHash: `sha256:${"2".repeat(64)}` },
    { ...expected, action: "records:write" },
    { ...expected, actionSensitivity: ActionSensitivity.CRITICAL },
    { ...expected, resourceId: "record:customer-8" },
    { ...expected, contextHash: `sha256:${"0".repeat(64)}` },
    { ...expected, policyId: "policy:other" },
    { ...expected, policyVersion: `sha256:${"1".repeat(64)}` },
    { ...expected, credentialId: "credential:other" },
    { ...expected, decision: "DENY", reasonCode: "POLICY_DENY" },
    { ...expected, decision: "DENY", reasonCode: "ACTION_NOT_PERMITTED" },
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
    () => signReceipt(
      receiptPayload(decision, { decision: "ALLOW", reasonCode: "POLICY_DENY" }),
      KEY,
      harness.authority,
    ),
    DomainValidationError,
  );
  assert.throws(
    () => signReceipt(
      receiptPayload(decision, { decision: "STEP_UP", reasonCode: "POLICY_ALLOW" }),
      KEY,
      harness.authority,
    ),
    DomainValidationError,
  );
  assert.throws(
    () => signReceipt(
      receiptPayload(decision, { decision: "DENY", reasonCode: "POLICY_ALLOW" }),
      KEY,
      harness.authority,
    ),
    DomainValidationError,
  );
  for (const fabricated of [
    { ...receiptPayload(decision), action: "records:delete" },
    { ...receiptPayload(decision), resourceId: "record:forbidden" },
    { ...receiptPayload(decision), policyId: "policy:untrusted" },
  ]) {
    assert.throws(
      () => signReceipt(fabricated, KEY, harness.authority),
      DomainValidationError,
    );
  }
});

test("15 non-authorizing DENY and STEP_UP receipts are never consumed", async () => {
  const harness = createHarness();
  const deny = evaluate(harness, { action: "records:delete" });
  const denyReceipt = signReceipt(receiptPayload(deny), KEY, harness.authority);
  const store = new InMemoryAtomicNonceStore();
  assert.deepEqual(
    await verifyAndConsumeReceipt(denyReceipt, KEY, store, harness.authority, {
      at: DECIDED_AT,
      expected: expectedReceiptBinding(deny),
    }),
    { valid: false, reasonCode: "RECEIPT_NOT_AUTHORIZING" },
  );
  const stepUp = evaluate(harness, { action: "records:export" });
  const stepUpReceipt = signReceipt(
    receiptPayload(stepUp, { nonce: "nonce:step-up" }),
    KEY,
    harness.authority,
  );
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
  const receipt = signReceipt(receiptPayload(decision), KEY, harness.authority);
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
  const receipt = signReceipt(receiptPayload(decision), KEY, harness.authority);
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
    harness.authority,
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
  const receipt = signReceipt(receiptPayload(decision), KEY, harness.authority);
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

test("18a delegated ALLOW receipts sign, inspect and consume without delegated scope on acting identity", async () => {
  const harness = createDelegationHarness();
  const decision = evaluateDelegated(harness);
  assert.equal(decision.outcome, "ALLOW");
  assert.deepEqual(harness.delegateIdentityCredential.allowedActions, []);
  assert.deepEqual(harness.delegateIdentityCredential.allowedResourceIds, []);
  const receipt = signReceipt(
    receiptPayload(decision, { nonce: "nonce:delegated-receipt" }),
    KEY,
    harness.credentialAuthority,
    harness.delegationAuthority,
  );
  const expected = expectedReceiptBinding(decision);
  assert.deepEqual(
    verifyReceipt(receipt, KEY, {
      at: DECIDED_AT,
      expected: {
        authorityMode: "DELEGATED",
        subjectType: PrincipalType.AGENT,
        actingCredentialId: harness.delegateIdentityCredential.id,
        effectiveScopeHash: harness.delegation.scopeHash,
        grantorCredentialId: harness.grantorCredential.id,
        delegationId: harness.delegation.id,
        delegationBindingHash: harness.delegation.delegationBindingHash,
      },
    }),
    { valid: true, reasonCode: "RECEIPT_VALID" },
  );
  assert.deepEqual(
    await verifyAndConsumeReceipt(
      receipt,
      KEY,
      new InMemoryAtomicNonceStore(),
      harness.credentialAuthority,
      { at: DECIDED_AT, expected, delegationAuthority: harness.delegationAuthority },
    ),
    { valid: true, reasonCode: "RECEIPT_VALID" },
  );
});

test("18b delegated receipt consumption rejects redirects for every authority binding", async () => {
  const harness = createDelegationHarness();
  const decision = evaluateDelegated(harness);
  const receipt = signReceipt(
    receiptPayload(decision, { nonce: "nonce:delegated-redirect" }),
    KEY,
    harness.credentialAuthority,
    harness.delegationAuthority,
  );
  const expected = expectedReceiptBinding(decision);
  assert.equal(expected.authorityMode, "DELEGATED");
  if (expected.authorityMode !== "DELEGATED") return;
  const redirects: readonly ReceiptExpectedBinding[] = [
    { ...expected, authorityMode: "DIRECT" } as ReceiptExpectedBinding,
    { ...expected, subjectId: "principal:other-delegate" },
    { ...expected, subjectType: PrincipalType.HUMAN },
    { ...expected, actingCredentialId: "credential:other-acting" },
    { ...expected, effectiveScopeHash: `sha256:${"1".repeat(64)}` },
    { ...expected, action: "records:write" },
    { ...expected, actionSensitivity: ActionSensitivity.SENSITIVE },
    { ...expected, resourceId: "record:2" },
    { ...expected, contextHash: `sha256:${"2".repeat(64)}` },
    { ...expected, policyId: "policy:other" },
    { ...expected, policyVersion: `sha256:${"3".repeat(64)}` },
    { ...expected, grantorId: "principal:other-grantor" },
    { ...expected, grantorType: PrincipalType.HUMAN },
    { ...expected, grantorCredentialId: "credential:other-grantor" },
    { ...expected, delegationId: "delegation:other" },
    { ...expected, delegationBindingHash: `sha256:${"4".repeat(64)}` },
    { ...expected, decision: "DENY", reasonCode: "POLICY_DENY" },
    { ...expected, decision: "DENY", reasonCode: "ACTION_NOT_PERMITTED" },
  ];
  const store = new InMemoryAtomicNonceStore();
  for (const redirected of redirects) {
    assert.deepEqual(
      await verifyAndConsumeReceipt(receipt, KEY, store, harness.credentialAuthority, {
        at: DECIDED_AT,
        expected: redirected,
        delegationAuthority: harness.delegationAuthority,
      }),
      { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" },
    );
  }
  assert.deepEqual(
    await verifyAndConsumeReceipt(receipt, KEY, store, harness.credentialAuthority, {
      at: DECIDED_AT,
      expected,
    }),
    { valid: false, reasonCode: "RECEIPT_AUTHORITY_INVALID" },
  );
});

test("18c delegated receipts revalidate acting, grantor and delegation revocation after signing", async () => {
  const cases = ["acting", "grantor", "delegation"] as const;
  for (const authority of cases) {
    const harness = createDelegationHarness();
    const decision = evaluateDelegated(harness);
    const receipt = signReceipt(
      receiptPayload(decision, { nonce: `nonce:revoked-${authority}` }),
      KEY,
      harness.credentialAuthority,
      harness.delegationAuthority,
    );
    if (authority === "acting") {
      harness.credentialAuthority.revokeCredential(harness.delegateIdentityCredential.id, {
        revokedAt: APPROVED_AT,
        reason: "acting-revoked-after-signing",
      });
    } else if (authority === "grantor") {
      harness.credentialAuthority.revokeCredential(harness.grantorCredential.id, {
        revokedAt: APPROVED_AT,
        reason: "grantor-revoked-after-signing",
      });
    } else {
      harness.delegationAuthority.revokeDelegation(harness.delegation.id, {
        revokedAt: APPROVED_AT,
        reason: "delegation-revoked-after-signing",
      });
    }
    assert.deepEqual(
      await verifyAndConsumeReceipt(
        receipt,
        KEY,
        new InMemoryAtomicNonceStore(),
        harness.credentialAuthority,
        {
          at: "2026-06-01T00:12:00.000Z",
          expected: expectedReceiptBinding(decision),
          delegationAuthority: harness.delegationAuthority,
        },
      ),
      { valid: false, reasonCode: "RECEIPT_AUTHORITY_INVALID" },
    );
  }
});

test("18d receipt signing caps authority expiry and rejects cross-authority configuration", async () => {
  const direct = createHarness({ credentialExpiresAt: "2026-06-01T00:15:00.000Z" });
  const directDecision = evaluate(direct);
  assert.throws(
    () => signReceipt(receiptPayload(directDecision), KEY, direct.authority),
    DomainValidationError,
  );
  const wrongCredentialAuthority = new CredentialAuthority({
    issuerId: "issuer:other",
    policyRegistry: new PolicyRegistry({ policies: [direct.policy] }),
  });
  assert.throws(
    () => signReceipt(receiptPayload(directDecision, { expiresAt: "2026-06-01T00:14:00.000Z" }), KEY, wrongCredentialAuthority),
    DomainValidationError,
  );

  const delegated = createDelegationHarness({
    delegationExpiresAt: "2026-06-01T00:15:00.000Z",
  });
  const delegatedDecision = evaluateDelegated(delegated);
  assert.throws(
    () => signReceipt(
      receiptPayload(delegatedDecision),
      KEY,
      delegated.credentialAuthority,
      delegated.delegationAuthority,
    ),
    DomainValidationError,
  );
  const crossDelegationAuthority = new DelegationAuthority({
    issuerId: "delegation-issuer:cross",
    credentialAuthority: wrongCredentialAuthority,
  });
  assert.throws(
    () => signReceipt(
      receiptPayload(delegatedDecision, { expiresAt: "2026-06-01T00:14:00.000Z" }),
      KEY,
      delegated.credentialAuthority,
      crossDelegationAuthority,
    ),
    DomainValidationError,
  );
  const validReceipt = signReceipt(
    receiptPayload(delegatedDecision, {
      nonce: "nonce:cross-authority-consume",
      expiresAt: "2026-06-01T00:14:00.000Z",
    }),
    KEY,
    delegated.credentialAuthority,
    delegated.delegationAuthority,
  );
  assert.deepEqual(
    await verifyAndConsumeReceipt(
      validReceipt,
      KEY,
      new InMemoryAtomicNonceStore(),
      delegated.credentialAuthority,
      {
        at: DECIDED_AT,
        expected: expectedReceiptBinding(delegatedDecision),
        delegationAuthority: crossDelegationAuthority,
      },
    ),
    { valid: false, reasonCode: "RECEIPT_AUTHORITY_INVALID" },
  );
});

test("18e receipt v2 is strict and policy/scope tampering invalidates its domain-separated signature", () => {
  const harness = createDelegationHarness();
  const decision = evaluateDelegated(harness);
  const payload = receiptPayload(decision);
  const receipt = signReceipt(
    payload,
    KEY,
    harness.credentialAuthority,
    harness.delegationAuthority,
  );
  for (const patch of [
    { policyVersion: `sha256:${"5".repeat(64)}` },
    { effectiveScopeHash: `sha256:${"6".repeat(64)}` },
    { delegationBindingHash: `sha256:${"7".repeat(64)}` },
  ]) {
    assert.equal(
      verifyReceipt({ ...receipt, payload: { ...receipt.payload, ...patch } }, KEY, {
        at: DECIDED_AT,
      }).reasonCode,
      "RECEIPT_SIGNATURE_INVALID",
    );
  }
  assert.throws(
    () => signReceipt(
      { ...payload, unexpected: true } as unknown as ReceiptPayload,
      KEY,
      harness.credentialAuthority,
      harness.delegationAuthority,
    ),
    DomainValidationError,
  );
  const directHarness = createHarness();
  const directDecision = evaluate(directHarness);
  const allowWithApprover = {
    ...receiptPayload(directDecision),
    requiredApproverCapability: "approval:records-read",
  } as ReceiptPayload;
  assert.throws(
    () => signReceipt(allowWithApprover, KEY, directHarness.authority),
    DomainValidationError,
  );
  const stepUpDecision = evaluate(directHarness, { action: "records:export" });
  const { requiredApproverCapability: _required, ...stepUpWithoutApprover } = receiptPayload(stepUpDecision);
  assert.throws(
    () => signReceipt(stepUpWithoutApprover as ReceiptPayload, KEY, directHarness.authority),
    DomainValidationError,
  );
  assert.deepEqual(
    verifyReceipt(receipt, KEY, {
      at: DECIDED_AT,
      expected: { subjectId: undefined } as never,
    }),
    { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" },
  );
  const scopedHarness = createHarness({
    credentialAllowedActions: ["records:read"],
    credentialAllowedResourceIds: ["record:customer-7"],
  });
  const outsideScope = evaluate(scopedHarness, { action: "records:publish" });
  assert.equal(outsideScope.reasonCode, "ACTION_OUTSIDE_CREDENTIAL_SCOPE");
  assert.throws(
    () => signReceipt(receiptPayload(outsideScope), KEY, scopedHarness.authority),
    DomainValidationError,
  );
});

test("18f 32 concurrent delegated receipt replays yield exactly one authorization", async () => {
  const harness = createDelegationHarness();
  const decision = evaluateDelegated(harness);
  const receipt = signReceipt(
    receiptPayload(decision, { nonce: "nonce:delegated-concurrent" }),
    KEY,
    harness.credentialAuthority,
    harness.delegationAuthority,
  );
  const store = new InMemoryAtomicNonceStore();
  const attempts = await Promise.all(
    Array.from({ length: 32 }, () =>
      verifyAndConsumeReceipt(receipt, KEY, store, harness.credentialAuthority, {
        at: DECIDED_AT,
        expected: expectedReceiptBinding(decision),
        delegationAuthority: harness.delegationAuthority,
      }),
    ),
  );
  assert.equal(attempts.filter((attempt) => attempt.valid).length, 1);
  assert.equal(attempts.filter((attempt) => attempt.reasonCode === "RECEIPT_REPLAYED").length, 31);
});

test("18g receipt anti-replay storage is domain-separated and fails closed on storage errors", async () => {
  const harness = createHarness();
  const decision = evaluate(harness);
  const receipt = signReceipt(
    receiptPayload(decision, { nonce: "nonce:anti-replay-storage" }),
    KEY,
    harness.authority,
  );
  const options = { at: DECIDED_AT, expected: expectedReceiptBinding(decision) };
  const throwingStore = {
    async consume(): Promise<boolean> {
      throw new Error("storage unavailable");
    },
  };
  assert.deepEqual(
    await verifyAndConsumeReceipt(receipt, KEY, throwingStore, harness.authority, options),
    { valid: false, reasonCode: "RECEIPT_REPLAYED" },
  );
  let observedNonce = "";
  const recordingStore = {
    async consume(nonce: string): Promise<boolean> {
      observedNonce = nonce;
      return true;
    },
  };
  assert.deepEqual(
    await verifyAndConsumeReceipt(receipt, KEY, recordingStore, harness.authority, options),
    { valid: true, reasonCode: "RECEIPT_VALID" },
  );
  assert.match(observedNonce, /^receipt-v2:[0-9a-f]{64}$/);
  assert.equal(observedNonce.startsWith("step-up-authorization:"), false);
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
      allowedActions: ["records:read"],
      allowedResourceIds: ["record:customer-7"],
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
  const registry = new PolicyRegistry({ policies: [harness.policy, changed] });
  assert.deepEqual(registry.resolve(harness.policy.id, harness.policy.version), harness.policy);
  assert.deepEqual(registry.resolve(changed.id, changed.version), changed);
  assert.equal("register" in registry, false);
  assert.equal("remove" in registry, false);
  assert.throws(
    () => new PolicyRegistry({ policies: [harness.policy, same] }),
    DomainValidationError,
  );
});

type PublicFixtureOperation = "issueCredential" | "evaluate";
interface PublicFixtureStep {
  readonly op: PublicFixtureOperation;
  readonly at: string;
  readonly as: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly expect: Readonly<Record<string, unknown>> & { readonly status: number };
}
interface PublicFixtureTranscript {
  readonly name: string;
  readonly fixed: {
    readonly initialClock: string;
    readonly referenceKeyBytes: readonly number[];
    readonly idsByKind: Readonly<Record<string, readonly string[]>>;
  };
  readonly steps: readonly PublicFixtureStep[];
}
interface PublicFixtureDocument {
  readonly version: 1;
  readonly transcripts: readonly PublicFixtureTranscript[];
}

function fixtureRecord(value: unknown, label: string): Record<string, unknown> {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must be an object`);
  assert.equal(Array.isArray(value), false, `${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  assert.ok(prototype === Object.prototype || prototype === null, `${label} must be plain`);
  return value as Record<string, unknown>;
}

function fixtureExact(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): Record<string, unknown> {
  const output = fixtureRecord(value, label);
  const allowed = new Set([...required, ...optional]);
  assert.deepEqual(Object.keys(output).filter((key) => !allowed.has(key)), [], `${label} has unknown fields`);
  required.forEach((key) => assert.ok(Object.hasOwn(output, key), `${label}.${key} is required`));
  return output;
}

function fixtureTimestamp(value: unknown, label: string): string {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.equal(new Date(value as string).toISOString(), value, `${label} must be canonical`);
  return value as string;
}

function fixtureStrings(value: unknown, label: string): readonly string[] {
  assert.ok(Array.isArray(value), `${label} must be an array`);
  value.forEach((entry, index) => assert.equal(typeof entry, "string", `${label}[${index}] must be a string`));
  return value as readonly string[];
}

function validatePublicFixture(value: unknown): PublicFixtureDocument {
  const root = fixtureExact(value, ["version", "transcripts"], [], "fixture");
  assert.equal(root.version, 1);
  assert.ok(Array.isArray(root.transcripts) && root.transcripts.length > 0);
  const names = new Set<string>();
  (root.transcripts as unknown[]).forEach((entry, transcriptIndex) => {
    const transcript = fixtureExact(entry, ["name", "fixed", "steps"], [], `transcripts[${transcriptIndex}]`);
    assert.equal(typeof transcript.name, "string");
    assert.equal(names.has(transcript.name as string), false);
    names.add(transcript.name as string);
    const fixed = fixtureExact(
      transcript.fixed,
      ["initialClock", "referenceKeyBytes", "idsByKind"],
      [],
      `${transcript.name}.fixed`,
    );
    fixtureTimestamp(fixed.initialClock, `${transcript.name}.fixed.initialClock`);
    assert.ok(Array.isArray(fixed.referenceKeyBytes) && fixed.referenceKeyBytes.length === 32);
    fixed.referenceKeyBytes.forEach((byte) => assert.ok(Number.isInteger(byte) && (byte as number) >= 0 && (byte as number) <= 255));
    const ids = fixtureExact(
      fixed.idsByKind,
      ["credential", "delegation", "decision-log", "step-up-request", "receipt-nonce"],
      [],
      `${transcript.name}.fixed.idsByKind`,
    );
    Object.entries(ids).forEach(([kind, list]) => fixtureStrings(list, `${transcript.name}.fixed.idsByKind.${kind}`));
    assert.ok(Array.isArray(transcript.steps) && transcript.steps.length > 0);
    const handles = new Set<string>();
    transcript.steps.forEach((stepValue, stepIndex) => {
      const label = `${transcript.name}.steps[${stepIndex}]`;
      const step = fixtureExact(stepValue, ["op", "at", "as", "input", "expect"], [], label);
      assert.ok(step.op === "issueCredential" || step.op === "evaluate");
      fixtureTimestamp(step.at, `${label}.at`);
      assert.match(step.as as string, /^[a-z][a-z0-9-]*$/);
      assert.equal(handles.has(step.as as string), false);
      handles.add(step.as as string);
      if (step.op === "issueCredential") {
        const input = fixtureExact(
          step.input,
          ["principal", "capabilities", "allowedActions", "allowedResourceIds", "expiresAt"],
          ["unverifiedMetadata"],
          `${label}.input`,
        );
        createPrincipal(input.principal);
        fixtureStrings(input.capabilities, `${label}.input.capabilities`);
        fixtureStrings(input.allowedActions, `${label}.input.allowedActions`);
        fixtureStrings(input.allowedResourceIds, `${label}.input.allowedResourceIds`);
        fixtureTimestamp(input.expiresAt, `${label}.input.expiresAt`);
        const expectation = fixtureExact(step.expect, ["status"], [], `${label}.expect`);
        assert.equal(expectation.status, 201);
      } else {
        const input = fixtureExact(
          step.input,
          ["authorityMode", "credential", "action", "resourceId", "actionContext", "policy", "issueReceipt"],
          ["receiptExpiresAt"],
          `${label}.input`,
        );
        assert.equal(input.authorityMode, "DIRECT");
        assert.match(input.credential as string, /^\$[a-z][a-z0-9-]*$/);
        assert.equal(typeof input.action, "string");
        assert.equal(typeof input.resourceId, "string");
        fixtureRecord(input.actionContext, `${label}.input.actionContext`);
        createPolicy(input.policy);
        assert.equal(typeof input.issueReceipt, "boolean");
        const expectation = fixtureExact(
          step.expect,
          ["status", "outcome", "reasonCode"],
          [],
          `${label}.expect`,
        );
        assert.equal(expectation.status, 200);
      }
    });
  });
  return value as PublicFixtureDocument;
}

test("21 checked-in versioned public fixtures validate strictly and execute through core contracts", async () => {
  const url = new URL("../../fixtures/public-api-cases.json", import.meta.url);
  const fixture = validatePublicFixture(JSON.parse(await readFile(url, "utf8")));
  const unknown = structuredClone(fixture) as unknown as Record<string, unknown>;
  (unknown.transcripts as Record<string, unknown>[])[0]!.unexpected = true;
  assert.throws(() => validatePublicFixture(unknown), /unknown fields/);

  for (const transcript of fixture.transcripts) {
    const registeredPolicies = transcript.steps
      .filter((step) => step.op === "evaluate")
      .map((step) => createPolicy(step.input.policy));
    const authority = new CredentialAuthority({
      issuerId: `issuer:${transcript.name}`,
      policyRegistry: new PolicyRegistry({ policies: registeredPolicies }),
    });
    const credentialIds = [...(transcript.fixed.idsByKind.credential ?? [])];
    const handles = new Map<string, unknown>();
    for (const step of transcript.steps) {
      if (step.op === "issueCredential") {
        const input = step.input;
        const principal = createPrincipal(input.principal);
        const id = credentialIds.shift();
        assert.ok(id, `${transcript.name} exhausted credential IDs`);
        const credential = authority.issueCredential({
          id,
          principal,
          capabilities: input.capabilities as readonly string[],
          allowedActions: input.allowedActions as readonly string[],
          allowedResourceIds: input.allowedResourceIds as readonly string[],
          issuedAt: step.at,
          expiresAt: input.expiresAt as string,
          ...(input.unverifiedMetadata === undefined
            ? {}
            : { unverifiedMetadata: input.unverifiedMetadata as never }),
        });
        handles.set(step.as, credential);
        assert.equal(step.expect.status, 201);
      } else {
        const input = step.input;
        const reference = input.credential as string;
        const credential = handles.get(reference.slice(1)) as Credential | undefined;
        assert.ok(credential, `${transcript.name} did not resolve ${reference}`);
        const principal = createPrincipal({
          id: credential.principalId,
          type: credential.principalType,
          affiliations: credential.affiliations,
        });
        const decision = evaluateAccess({
          authorityMode: "DIRECT",
          principal,
          credential,
          action: input.action,
          resourceId: input.resourceId,
          actionContext: input.actionContext,
          policy: createPolicy(input.policy),
          at: step.at,
          credentialAuthority: authority,
        });
        assert.equal(decision.outcome, step.expect.outcome, transcript.name);
        assert.equal(decision.reasonCode, step.expect.reasonCode, transcript.name);
        handles.set(step.as, decision);
      }
    }
    assert.deepEqual(credentialIds, [], `${transcript.name} left unused credential IDs`);
  }
});

test("22 canonical JSON preserves __proto__ as data and prevents context-hash collision", () => {
  const withProtoKey = JSON.parse('{"__proto__":{"admin":true}}') as Record<string, unknown>;
  assert.equal(canonicalJson(withProtoKey), '{"__proto__":{"admin":true}}');
  assert.notEqual(sha256Version(withProtoKey), sha256Version({}));
});

test("23 principal type is exact, required and unknown-field fail-closed", () => {
  for (const type of [PrincipalType.HUMAN, PrincipalType.ORGANIZATION, PrincipalType.AGENT]) {
    assert.equal(createPrincipal({ id: `principal:${type.toLowerCase()}`, type, affiliations: [] }).type, type);
  }
  assert.throws(
    () => createPrincipal({ id: "principal:missing-type", affiliations: [] }),
    DomainValidationError,
  );
  assert.throws(
    () => createPrincipal({ id: "principal:bad-type", type: "SERVICE", affiliations: [] }),
    DomainValidationError,
  );
  assert.throws(
    () => createPrincipal({
      id: "principal:unknown-field",
      type: PrincipalType.AGENT,
      affiliations: [],
      trusted: true,
    }),
    DomainValidationError,
  );
});

test("24 credential v2 canonicalizes and independently hashes exact deny-all-capable scope", () => {
  const authority = new CredentialAuthority({
    issuerId: "issuer:scope",
    policyRegistry: new PolicyRegistry({ policies: [] }),
  });
  const principal = createPrincipal({
    id: "principal:scope",
    type: PrincipalType.AGENT,
    affiliations: [
      { organizationId: "organization:z", role: "member" },
      { organizationId: "organization:A", role: "member" },
    ],
  });
  const credential = authority.issueCredential({
    id: "credential:scope",
    principal,
    capabilities: ["records:a", "Records:Z"],
    allowedActions: ["records:a", "Records:Z"],
    allowedResourceIds: ["resource:a", "resource:Z"],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  assert.equal(credential.version, 2);
  assert.deepEqual(
    [credential.principalId, credential.principalType],
    [principal.id, PrincipalType.AGENT],
  );
  assert.deepEqual(credential.affiliations, [
    { organizationId: "organization:A", role: "member" },
    { organizationId: "organization:z", role: "member" },
  ]);
  assert.deepEqual(credential.capabilities, ["Records:Z", "records:a"]);
  assert.deepEqual(credential.allowedActions, ["Records:Z", "records:a"]);
  assert.deepEqual(credential.allowedResourceIds, ["resource:Z", "resource:a"]);
  assert.equal(credential.scopeHash, computeScopeHash({
    capabilities: ["records:a", "Records:Z"],
    allowedActions: ["records:a", "Records:Z"],
    allowedResourceIds: ["resource:a", "resource:Z"],
  }));
  assert.equal(credential.scopeHash, sha256Version({
    domain: "zkyc-scope",
    version: 1,
    capabilities: ["Records:Z", "records:a"],
    allowedActions: ["Records:Z", "records:a"],
    allowedResourceIds: ["resource:Z", "resource:a"],
  }));

  const denyAll = authority.issueCredential({
    id: "credential:deny-all",
    principal,
    capabilities: [],
    allowedActions: [],
    allowedResourceIds: [],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  assert.deepEqual(
    [denyAll.capabilities, denyAll.allowedActions, denyAll.allowedResourceIds],
    [[], [], []],
  );
  assert.deepEqual(authority.checkCredential(denyAll, DECIDED_AT), { valid: true, code: "ACTIVE" });
  assert.deepEqual(
    authority.checkCredentialById(credential.id, DECIDED_AT, principal.id, PrincipalType.HUMAN),
    { valid: false, code: "CREDENTIAL_UNKNOWN" },
  );

  const base = {
    id: "credential:invalid",
    principal,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:1"],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  };
  for (const invalid of [
    { ...base, allowedActions: undefined },
    { ...base, capabilities: ["records:read", "records:read"] },
    { ...base, allowedActions: ["records:read", "records:read"] },
    { ...base, allowedResourceIds: ["record:1", "record:1"] },
    { ...base, capabilities: ["*"] },
    { ...base, allowedActions: ["records:*"] },
    { ...base, allowedResourceIds: ["*"] },
    { ...base, issuedAt: "2026-06-01T00:00:00Z" },
    { ...base, unsupported: true },
  ]) {
    assert.throws(() => authority.issueCredential(invalid as never), DomainValidationError);
  }
  assert.throws(
    () => authority.issueCredential({
      ...base,
      principal: {
        ...principal,
        affiliations: [principal.affiliations[0], principal.affiliations[0]],
      } as Principal,
    }),
    DomainValidationError,
  );
  assert.deepEqual(
    authority.checkCredential({ ...credential, scopeHash: `sha256:${"0".repeat(64)}` }, DECIDED_AT),
    { valid: false, code: "CREDENTIAL_MALFORMED" },
  );
});

test("25 delegation issuance binds authority, root identity, policy, attenuated scope and time", () => {
  const harness = createDelegationHarness();
  const { delegation } = harness;
  assert.equal(delegation.version, 1);
  assert.equal(delegation.issuerId, harness.delegationAuthority.issuerId);
  assert.equal(delegation.grantorCredentialId, harness.grantorCredential.id);
  assert.deepEqual(
    [delegation.grantorId, delegation.grantorType],
    [harness.grantor.id, harness.grantor.type],
  );
  assert.deepEqual(
    [delegation.delegateId, delegation.delegateType],
    [harness.delegate.id, harness.delegate.type],
  );
  assert.deepEqual(
    [delegation.policyId, delegation.policyVersion],
    [harness.policy.id, harness.policy.version],
  );
  assert.deepEqual(delegation.capabilities, ["records:read"]);
  assert.deepEqual(delegation.allowedActions, ["records:read"]);
  assert.deepEqual(delegation.allowedResourceIds, ["record:1"]);
  assert.equal(delegation.scopeHash, computeScopeHash({
    capabilities: delegation.capabilities,
    allowedActions: delegation.allowedActions,
    allowedResourceIds: delegation.allowedResourceIds,
  }));
  assert.equal(delegation.delegationBindingHash, computeDelegationBindingHash(delegation));

  const base = {
    id: "delegation:invalid",
    grantor: harness.grantor,
    grantorCredential: harness.grantorCredential,
    delegate: harness.delegate,
    policy: harness.policy,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:1"],
    issuedAt: DECIDED_AT,
    expiresAt: EXPIRES_AT,
  };
  const expectCode = (input: unknown, code: string) => {
    assert.throws(
      () => harness.delegationAuthority.issueDelegation(input as never),
      (error: unknown) => error instanceof DelegationValidationError && error.code === code,
    );
  };
  for (const axis of ["capabilities", "allowedActions", "allowedResourceIds"] as const) {
    expectCode({ ...base, [axis]: [] }, "DELEGATION_MALFORMED");
  }
  expectCode({ ...base, capabilities: ["records:export"] }, "DELEGATION_SCOPE_ESCALATION");
  expectCode({ ...base, allowedActions: ["records:export"] }, "DELEGATION_SCOPE_ESCALATION");
  expectCode({ ...base, allowedResourceIds: ["record:9"] }, "DELEGATION_SCOPE_ESCALATION");
  expectCode({ ...base, capabilities: ["records:read", "records:read"] }, "DELEGATION_MALFORMED");
  expectCode({ ...base, issuerId: "caller:forged" }, "DELEGATION_MALFORMED");
  expectCode({ ...base, grantorDelegation: delegation }, "DELEGATION_MALFORMED");
  expectCode({ ...base, delegate: harness.grantor }, "DELEGATION_IDENTITIES_NOT_DISTINCT");
  expectCode({ ...base, grantorCredential: delegation }, "DELEGATION_GRANTOR_CREDENTIAL_INVALID");
  expectCode({
    ...base,
    grantorCredential: { ...harness.grantorCredential, allowedActions: ["records:read"] },
  }, "DELEGATION_GRANTOR_CREDENTIAL_INVALID");
  expectCode({
    ...base,
    grantor: createPrincipal({
      id: "principal:other",
      type: PrincipalType.ORGANIZATION,
      affiliations: [],
    }),
  }, "DELEGATION_GRANTOR_MISMATCH");
  expectCode({
    ...base,
    grantor: createPrincipal({
      ...harness.grantor,
      affiliations: [{ organizationId: "organization:forged", role: "admin" }],
    }),
  }, "DELEGATION_GRANTOR_MISMATCH");
  expectCode({ ...base, expiresAt: DECIDED_AT }, "DELEGATION_TIME_INVALID");
  expectCode({ ...base, expiresAt: "2026-06-01T02:00:00.000Z" }, "DELEGATION_TIME_INVALID");
  expectCode({ ...base, issuedAt: "2026-06-01T00:10:00Z" }, "DELEGATION_MALFORMED");
  expectCode({
    ...base,
    policy: { ...harness.policy, version: `sha256:${"0".repeat(64)}` },
  }, "DELEGATION_POLICY_INVALID");

  const redelegationAuthority = new CredentialAuthority({
    issuerId: "issuer:redelegation",
    policyRegistry: new PolicyRegistry({ policies: [harness.policy] }),
  });
  const redelegationGrantorCredential = redelegationAuthority.issueCredential({
    id: "credential:redelegation",
    principal: harness.grantor,
    capabilities: ["delegation:issue"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:1"],
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  const redelegation = new DelegationAuthority({
    issuerId: "delegation-issuer:redelegation",
    credentialAuthority: redelegationAuthority,
  });
  assert.throws(
    () => redelegation.issueDelegation({
      ...base,
      id: "delegation:redelegation",
      grantorCredential: redelegationGrantorCredential,
      capabilities: ["delegation:issue"],
    }),
    (error: unknown) => error instanceof DelegationValidationError &&
      error.code === "DELEGATION_REDELEGATION_NOT_ALLOWED",
  );
});

test("26 delegated ALLOW is deterministic and binds distinct acting, grantor and delegation authority", () => {
  const harness = createDelegationHarness();
  const first = evaluateDelegated(harness);
  const second = evaluateDelegated(harness, {
    actionContext: { purpose: "delegated-review", fields: ["name"] },
  });
  assert.deepEqual(first, second);
  assert.equal(first.version, 2);
  assert.equal(first.outcome, "ALLOW");
  assert.equal(first.reasonCode, "POLICY_ALLOW");
  assert.equal(first.authorityMode, "DELEGATED");
  assert.equal(first.subjectId, harness.delegate.id);
  assert.equal(first.subjectType, harness.delegate.type);
  assert.equal(first.actingCredentialId, harness.delegateIdentityCredential.id);
  assert.equal(first.effectiveScopeHash, harness.delegation.scopeHash);
  assert.equal(first.grantorId, harness.grantor.id);
  assert.equal(first.grantorType, harness.grantor.type);
  assert.equal(first.grantorCredentialId, harness.grantorCredential.id);
  assert.equal(first.delegationId, harness.delegation.id);
  assert.equal(first.delegationBindingHash, harness.delegation.delegationBindingHash);
  assert.equal("credentialId" in first, false);
});

test("27 delegated policy affiliations come only from the delegate identity credential", () => {
  const policy = createPolicy({
    id: "policy:delegate-affiliation",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [MEMBER_AFFILIATION],
      effect: "ALLOW",
    }],
  });
  const inherited = createDelegationHarness({ policy });
  assert.equal(evaluateDelegated(inherited).reasonCode, "AFFILIATION_REQUIRED");

  const affiliatedDelegate = createPrincipal({
    id: "principal:affiliated-agent",
    type: PrincipalType.AGENT,
    affiliations: [MEMBER_AFFILIATION],
  });
  const bound = createDelegationHarness({ policy, delegate: affiliatedDelegate });
  assert.equal(evaluateDelegated(bound).outcome, "ALLOW");
});

test("28 delegated evaluation rejects delegate identity mismatch, inactivity and substitution", () => {
  const harness = createDelegationHarness();
  assert.equal(
    evaluateDelegated(harness, {
      delegateIdentityCredential: harness.grantorCredential,
    }).reasonCode,
    "DELEGATION_IDENTITIES_NOT_DISTINCT",
  );
  const wrongType = createPrincipal({
    id: harness.delegate.id,
    type: PrincipalType.HUMAN,
    affiliations: [],
  });
  assert.equal(
    evaluateDelegated(harness, { principal: wrongType }).reasonCode,
    "DELEGATION_DELEGATE_MISMATCH",
  );

  const expired = harness.credentialAuthority.issueCredential({
    id: "credential:delegate-expired",
    principal: harness.delegate,
    capabilities: [],
    allowedActions: [],
    allowedResourceIds: [],
    issuedAt: ISSUED_AT,
    expiresAt: "2026-06-01T00:05:00.000Z",
  });
  assert.equal(
    evaluateDelegated(harness, { delegateIdentityCredential: expired }).reasonCode,
    "CREDENTIAL_EXPIRED",
  );
  const future = harness.credentialAuthority.issueCredential({
    id: "credential:delegate-future",
    principal: harness.delegate,
    capabilities: [],
    allowedActions: [],
    allowedResourceIds: [],
    issuedAt: "2026-06-01T00:20:00.000Z",
    expiresAt: "2026-06-01T00:40:00.000Z",
  });
  assert.equal(
    evaluateDelegated(harness, { delegateIdentityCredential: future }).reasonCode,
    "CREDENTIAL_NOT_YET_VALID",
  );
  harness.credentialAuthority.revokeCredential(harness.delegateIdentityCredential.id, {
    revokedAt: "2026-06-01T00:09:00.000Z",
    reason: "delegate-disabled",
  });
  assert.equal(evaluateDelegated(harness).reasonCode, "CREDENTIAL_REVOKED");
});

test("29 delegated evaluation rejects grantor credential substitution and invalidity", () => {
  const harness = createDelegationHarness();
  const otherAuthority = new CredentialAuthority({
    issuerId: "issuer:cross-authority",
    policyRegistry: new PolicyRegistry({ policies: [harness.policy] }),
  });
  assert.equal(
    evaluateAccess({
      authorityMode: "DELEGATED",
      principal: harness.delegate,
      delegateIdentityCredential: harness.delegateIdentityCredential,
      grantorCredential: harness.grantorCredential,
      delegation: harness.delegation,
      action: "records:read",
      resourceId: "record:1",
      actionContext: { purpose: "cross-authority-substitution" },
      policy: harness.policy,
      at: DECIDED_AT,
      credentialAuthority: otherAuthority,
      delegationAuthority: harness.delegationAuthority,
    }).reasonCode,
    "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
  );
  const substitute = harness.credentialAuthority.issueCredential({
    id: "credential:grantor-substitute",
    principal: harness.grantor,
    capabilities: harness.grantorCredential.capabilities,
    allowedActions: harness.grantorCredential.allowedActions,
    allowedResourceIds: harness.grantorCredential.allowedResourceIds,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  });
  assert.equal(
    evaluateDelegated(harness, { grantorCredential: substitute }).reasonCode,
    "DELEGATION_GRANTOR_MISMATCH",
  );
  assert.equal(
    evaluateDelegated(harness, {
      grantorCredential: {
        ...harness.grantorCredential,
        scopeHash: `sha256:${"0".repeat(64)}`,
      },
    }).reasonCode,
    "DELEGATION_GRANTOR_CREDENTIAL_INVALID",
  );
});

test("30 delegated evaluation fails closed for mixed, unknown, malformed and unregistered inputs", () => {
  const direct = createHarness();
  assert.equal(
    evaluateAccess({
      authorityMode: "DIRECT",
      principal: direct.principal,
      credential: direct.credential,
      delegation: createDelegationHarness().delegation,
      action: "records:read",
      resourceId: "record:customer-7",
      actionContext: {},
      policy: direct.policy,
      at: DECIDED_AT,
      credentialAuthority: direct.authority,
    }).reasonCode,
    "INVALID_INPUT",
  );
  assert.equal(
    evaluateAccess({
      authorityMode: "CHAINED",
      principal: direct.principal,
      credential: direct.credential,
      action: "records:read",
      resourceId: "record:customer-7",
      actionContext: {},
      policy: direct.policy,
      at: DECIDED_AT,
      credentialAuthority: direct.authority,
    }).reasonCode,
    "INVALID_INPUT",
  );

  const harness = createDelegationHarness();
  const tampered = {
    ...harness.delegation,
    allowedResourceIds: ["record:2"],
  } as CapabilityDelegation;
  assert.equal(
    evaluateDelegated(harness, { delegation: tampered }).reasonCode,
    "DELEGATION_MALFORMED",
  );
  const unknownUnsigned = {
    ...harness.delegation,
    id: "delegation:unknown",
    delegationBindingHash: `sha256:${"0".repeat(64)}`,
  };
  const unknown = {
    ...unknownUnsigned,
    delegationBindingHash: computeDelegationBindingHash(unknownUnsigned),
  };
  assert.equal(
    evaluateDelegated(harness, { delegation: unknown }).reasonCode,
    "DELEGATION_UNKNOWN",
  );
});

test("31 delegated evaluation enforces validity windows and revocation", () => {
  const future = createDelegationHarness({
    delegationIssuedAt: "2026-06-01T00:20:00.000Z",
    delegationExpiresAt: "2026-06-01T00:40:00.000Z",
  });
  assert.equal(evaluateDelegated(future).reasonCode, "DELEGATION_NOT_YET_VALID");
  const expired = createDelegationHarness({
    delegationExpiresAt: "2026-06-01T00:05:00.000Z",
  });
  assert.equal(evaluateDelegated(expired).reasonCode, "DELEGATION_EXPIRED");
  const revoked = createDelegationHarness();
  revoked.delegationAuthority.revokeDelegation(revoked.delegation.id, {
    revokedAt: "2026-06-01T00:09:00.000Z",
    reason: "grantor-withdrawal",
  });
  assert.equal(evaluateDelegated(revoked).reasonCode, "DELEGATION_REVOKED");
});

test("32 delegated evaluation pins exact policy content", () => {
  const original = createPolicy({
    id: "policy:delegated-reference",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  });
  const changed = createPolicy({
    id: original.id,
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  });
  const harness = createDelegationHarness({
    policy: original,
    additionalTrustedPolicies: [changed],
  });
  assert.equal(
    evaluateDelegated(harness, { policy: changed }).reasonCode,
    "DELEGATION_POLICY_MISMATCH",
  );
});

test("33 delegated evaluation enforces action, resource and capability attenuation", () => {
  const scopedPolicy = createPolicy({
    id: "policy:delegated-scope",
    rules: [
      {
        action: "records:read",
        actionSensitivity: ActionSensitivity.ROUTINE,
        requiredCapabilities: ["records:read"],
        requiredAffiliations: [],
        effect: "ALLOW",
      },
      {
        action: "records:write",
        actionSensitivity: ActionSensitivity.SENSITIVE,
        requiredCapabilities: ["records:write"],
        requiredAffiliations: [],
        effect: "ALLOW",
      },
    ],
  });
  const harness = createDelegationHarness({ policy: scopedPolicy });
  assert.equal(
    evaluateDelegated(harness, { action: "records:write" }).reasonCode,
    "ACTION_OUTSIDE_DELEGATION_SCOPE",
  );
  assert.equal(
    evaluateDelegated(harness, { resourceId: "record:2" }).reasonCode,
    "RESOURCE_OUTSIDE_DELEGATION_SCOPE",
  );

  const capabilityPolicy = createPolicy({
    id: "policy:delegated-capability",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:write"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  });
  const insufficient = createDelegationHarness({ policy: capabilityPolicy });
  assert.equal(
    evaluateDelegated(insufficient).reasonCode,
    "INSUFFICIENT_DELEGATED_CAPABILITY",
  );
});

function createDelegatedStepUpHarness() {
  const policy = createPolicy({
    id: "policy:delegated-step-up",
    rules: [{
      action: "records:export",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:export"],
      requiredAffiliations: [],
      effect: "STEP_UP",
      approverCapability: "approval:records-export",
    }],
  });
  const harness = createDelegationHarness({
    policy,
    grantorCapabilities: ["records:export"],
    grantorAllowedActions: ["records:export"],
    grantorAllowedResourceIds: ["dataset:7"],
    delegatedCapabilities: ["records:export"],
    delegatedAllowedActions: ["records:export"],
    delegatedAllowedResourceIds: ["dataset:7"],
  });
  const decision = evaluateDelegated(harness, {
    action: "records:export",
    resourceId: "dataset:7",
  });
  assert.equal(decision.outcome, "STEP_UP");
  const service = new HumanStepUpService({
    credentialAuthority: harness.credentialAuthority,
    delegationAuthority: harness.delegationAuthority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  return { ...harness, decision, service };
}

test("34 delegated step-up preserves every authority binding and rejects redirects under 32-way replay", async () => {
  const harness = createDelegatedStepUpHarness();
  const request = harness.service.createRequest({
    id: "step-up:delegated-export",
    decision: harness.decision,
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  assert.equal(request.version, 2);
  assert.equal(request.authorityMode, "DELEGATED");
  if (request.authorityMode !== "DELEGATED") return;
  assert.equal(request.subjectType, PrincipalType.AGENT);
  assert.equal(request.actingCredentialId, harness.delegateIdentityCredential.id);
  assert.equal(request.effectiveScopeHash, harness.delegation.scopeHash);
  assert.equal(request.grantorId, harness.grantor.id);
  assert.equal(request.grantorType, harness.grantor.type);
  assert.equal(request.grantorCredentialId, harness.grantorCredential.id);
  assert.equal(request.delegationId, harness.delegation.id);
  assert.equal(request.delegationBindingHash, harness.delegation.delegationBindingHash);

  const approver = createApprover(harness.credentialAuthority, undefined, { id: "delegated-approver" });
  const resolved = await harness.service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: approver.principal,
    approverCredential: approver.credential,
    at: APPROVED_AT,
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok || resolved.authorization.authorityMode !== "DELEGATED") return;
  const authorization = resolved.authorization;
  assert.equal(authorization.version, 2);
  assert.equal(authorization.approvedByType, PrincipalType.HUMAN);
  assert.equal(authorization.approverCredentialId, approver.credential.id);
  assert.equal(authorization.delegationBindingHash, harness.delegation.delegationBindingHash);

  const base = {
    authorization,
    ...stepUpBinding(authorization),
    at: "2026-06-01T00:12:00.000Z",
  };
  const zeroHash = `sha256:${"0".repeat(64)}`;
  const redirects: readonly Record<string, unknown>[] = [
    { ...base, requestId: "step-up:other" },
    { ...base, authorityMode: "DIRECT" },
    { ...base, subjectId: "principal:other" },
    { ...base, subjectType: PrincipalType.HUMAN },
    { ...base, actingCredentialId: "credential:other" },
    { ...base, effectiveScopeHash: zeroHash },
    { ...base, action: "records:read" },
    { ...base, actionSensitivity: ActionSensitivity.CRITICAL },
    { ...base, resourceId: "dataset:8" },
    { ...base, contextHash: zeroHash },
    { ...base, policyId: "policy:other" },
    { ...base, policyVersion: zeroHash },
    { ...base, requiredApproverCapability: "approval:other" },
    { ...base, approvedBy: "principal:other" },
    { ...base, approvedByType: PrincipalType.AGENT },
    { ...base, approverCredentialId: "credential:other" },
    { ...base, grantorId: "principal:other" },
    { ...base, grantorType: PrincipalType.HUMAN },
    { ...base, grantorCredentialId: "credential:other" },
    { ...base, delegationId: "delegation:other" },
    { ...base, delegationBindingHash: zeroHash },
  ];
  for (const redirected of redirects) {
    assert.equal(
      await harness.service.consumeAuthorization(
        redirected as unknown as Parameters<HumanStepUpService["consumeAuthorization"]>[0],
      ),
      false,
    );
  }
  const winners = await Promise.all(
    Array.from({ length: 32 }, () => harness.service.consumeAuthorization(base)),
  );
  assert.equal(winners.filter(Boolean).length, 1);
});

test("35 step-up approval is human-only and action/resource scoped", async () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export", resourceId: "dataset:7" });
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const request = service.createRequest({
    id: "step-up:approver-scope",
    decision,
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  const agent = createApprover(harness.authority, undefined, {
    id: "agent-approver",
    type: PrincipalType.AGENT,
  });
  assert.deepEqual(
    await service.resolveRequest({
      requestId: request.id,
      resolution: "APPROVE",
      approver: agent.principal,
      approverCredential: agent.credential,
      at: APPROVED_AT,
    }),
    { ok: false, reasonCode: "APPROVER_CREDENTIAL_INVALID" },
  );
  const wrongAction = createApprover(harness.authority, undefined, {
    id: "wrong-action",
    allowedActions: ["records:read"],
  });
  assert.deepEqual(
    await service.resolveRequest({
      requestId: request.id,
      resolution: "APPROVE",
      approver: wrongAction.principal,
      approverCredential: wrongAction.credential,
      at: APPROVED_AT,
    }),
    { ok: false, reasonCode: "APPROVER_SCOPE_MISSING" },
  );
  const wrongResource = createApprover(harness.authority, undefined, {
    id: "wrong-resource",
    allowedResourceIds: ["dataset:8"],
  });
  assert.deepEqual(
    await service.resolveRequest({
      requestId: request.id,
      resolution: "APPROVE",
      approver: wrongResource.principal,
      approverCredential: wrongResource.credential,
      at: APPROVED_AT,
    }),
    { ok: false, reasonCode: "APPROVER_SCOPE_MISSING" },
  );
  const valid = createApprover(harness.authority, undefined, { id: "valid-human" });
  assert.equal((await service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: valid.principal,
    approverCredential: valid.credential,
    at: APPROVED_AT,
  })).ok, true);
});

test("35a step-up request creation rejects fabricated action, resource and policy authority", () => {
  const harness = createHarness();
  const decision = evaluate(harness, { action: "records:export", resourceId: "dataset:7" });
  assert.equal(decision.outcome, "STEP_UP");
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const attempts = [
    { ...decision, action: "records:delete" },
    { ...decision, resourceId: "dataset:forbidden" },
    { ...decision, policyId: "policy:untrusted" },
  ];
  attempts.forEach((fabricated, index) => {
    assert.throws(
      () => service.createRequest({
        id: `step-up:fabricated-${index}`,
        decision: fabricated,
        expiresAt: RECEIPT_EXPIRES_AT,
      }),
      DomainValidationError,
    );
  });
});

test("36 delegated step-up revalidates acting, grantor and delegation authority at every transition", async () => {
  const beforeResolutionCases = ["acting", "grantor", "delegation"] as const;
  for (const authority of beforeResolutionCases) {
    const harness = createDelegatedStepUpHarness();
    const request = harness.service.createRequest({
      id: `step-up:revoke-before:${authority}`,
      decision: harness.decision,
      expiresAt: RECEIPT_EXPIRES_AT,
    });
    if (authority === "acting") {
      harness.credentialAuthority.revokeCredential(harness.delegateIdentityCredential.id, {
        revokedAt: "2026-06-01T00:10:30.000Z",
        reason: "acting-revoked",
      });
    } else if (authority === "grantor") {
      harness.credentialAuthority.revokeCredential(harness.grantorCredential.id, {
        revokedAt: "2026-06-01T00:10:30.000Z",
        reason: "grantor-revoked",
      });
    } else {
      harness.delegationAuthority.revokeDelegation(harness.delegation.id, {
        revokedAt: "2026-06-01T00:10:30.000Z",
        reason: "delegation-revoked",
      });
    }
    const approver = createApprover(harness.credentialAuthority, undefined, { id: `before-${authority}` });
    assert.deepEqual(
      await harness.service.resolveRequest({
        requestId: request.id,
        resolution: "APPROVE",
        approver: approver.principal,
        approverCredential: approver.credential,
        at: APPROVED_AT,
      }),
      { ok: false, reasonCode: "SUBJECT_AUTHORITY_INVALID" },
    );
  }

  const afterApprovalCases = ["acting", "grantor", "delegation"] as const;
  for (const authority of afterApprovalCases) {
    const harness = createDelegatedStepUpHarness();
    const request = harness.service.createRequest({
      id: `step-up:revoke-after:${authority}`,
      decision: harness.decision,
      expiresAt: RECEIPT_EXPIRES_AT,
    });
    const approver = createApprover(harness.credentialAuthority, undefined, { id: `after-${authority}` });
    const resolved = await harness.service.resolveRequest({
      requestId: request.id,
      resolution: "APPROVE",
      approver: approver.principal,
      approverCredential: approver.credential,
      at: APPROVED_AT,
    });
    assert.equal(resolved.ok, true);
    if (!resolved.ok) continue;
    if (authority === "acting") {
      harness.credentialAuthority.revokeCredential(harness.delegateIdentityCredential.id, {
        revokedAt: "2026-06-01T00:11:30.000Z",
        reason: "acting-revoked",
      });
    } else if (authority === "grantor") {
      harness.credentialAuthority.revokeCredential(harness.grantorCredential.id, {
        revokedAt: "2026-06-01T00:11:30.000Z",
        reason: "grantor-revoked",
      });
    } else {
      harness.delegationAuthority.revokeDelegation(harness.delegation.id, {
        revokedAt: "2026-06-01T00:11:30.000Z",
        reason: "delegation-revoked",
      });
    }
    assert.equal(
      await harness.service.consumeAuthorization({
        authorization: resolved.authorization,
        ...stepUpBinding(resolved.authorization),
        at: "2026-06-01T00:12:00.000Z",
      }),
      false,
    );
  }
});

test("37 step-up expiry is capped by subject, delegation and approver artifacts", async () => {
  const direct = createHarness({ credentialExpiresAt: "2026-06-01T00:19:00.000Z" });
  const directService = new HumanStepUpService({
    credentialAuthority: direct.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  assert.throws(
    () => directService.createRequest({
      id: "step-up:direct-expiry-cap",
      decision: evaluate(direct, { action: "records:export", resourceId: "dataset:7" }),
      expiresAt: RECEIPT_EXPIRES_AT,
    }),
    DomainValidationError,
  );

  const delegated = createDelegatedStepUpHarness();
  const shortDelegation = createDelegationHarness({
    policy: delegated.policy,
    delegationExpiresAt: "2026-06-01T00:19:00.000Z",
    grantorCapabilities: ["records:export"],
    grantorAllowedActions: ["records:export"],
    grantorAllowedResourceIds: ["dataset:7"],
    delegatedCapabilities: ["records:export"],
    delegatedAllowedActions: ["records:export"],
    delegatedAllowedResourceIds: ["dataset:7"],
  });
  const shortService = new HumanStepUpService({
    credentialAuthority: shortDelegation.credentialAuthority,
    delegationAuthority: shortDelegation.delegationAuthority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  assert.throws(
    () => shortService.createRequest({
      id: "step-up:delegation-expiry-cap",
      decision: evaluateDelegated(shortDelegation, {
        action: "records:export",
        resourceId: "dataset:7",
      }),
      expiresAt: RECEIPT_EXPIRES_AT,
    }),
    DomainValidationError,
  );

  const harness = createHarness();
  const service = new HumanStepUpService({
    credentialAuthority: harness.authority,
    nonceStore: new InMemoryAtomicNonceStore(),
  });
  const request = service.createRequest({
    id: "step-up:approver-expiry-cap",
    decision: evaluate(harness, { action: "records:export", resourceId: "dataset:7" }),
    expiresAt: RECEIPT_EXPIRES_AT,
  });
  const approver = createApprover(harness.authority, undefined, {
    id: "short-lived-approver",
    expiresAt: "2026-06-01T00:11:30.000Z",
  });
  const resolved = await service.resolveRequest({
    requestId: request.id,
    resolution: "APPROVE",
    approver: approver.principal,
    approverCredential: approver.credential,
    at: APPROVED_AT,
  });
  assert.equal(resolved.ok, true);
  if (resolved.ok) assert.equal(resolved.authorization.expiresAt, "2026-06-01T00:11:30.000Z");
});
