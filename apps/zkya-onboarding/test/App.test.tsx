import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  ZkycApiError,
  ZkycTransportError,
  type AccessDecision,
  type CapabilityDelegation,
  type Credential,
  type OnboardingView,
  type SignedReceipt,
  type StepUpRequest,
} from "@ordin/zkyc-sdk-reference";
import { App } from "../src/App.js";
import type { OnboardingClient } from "../src/scenarios.js";

const hash = (character: string) => `sha256:${character.repeat(64)}`;
const now = "2026-08-10T12:00:00.000Z";
const later = "2026-08-10T13:00:00.000Z";

function view(overrides: Partial<OnboardingView> = {}): OnboardingView {
  return {
    version: 1,
    referenceOnly: true,
    decisionLogId: "decision-log:test",
    verificationStatus: "ACTIVE",
    principal: {
      id: "agent:test",
      type: "AGENT",
      affiliations: [],
    },
    authorityMode: "DIRECT",
    delegatedScope: null,
    eligibleActions: [{
      action: "records:read",
      resourceId: "record:test",
      status: "ELIGIBLE",
      reasonCode: "POLICY_ALLOW",
    }],
    requiredApproval: { status: "NOT_REQUIRED" },
    receipt: { status: "NOT_ISSUED" },
    policyId: "policy:test",
    policyVersion: hash("b"),
    ...overrides,
  };
}

function credential(input: Parameters<OnboardingClient["issueCredential"]>[0], id = "credential:test"): Credential {
  return {
    version: 2,
    id,
    issuerId: "issuer:test",
    principalId: input.principal.id,
    principalType: input.principal.type,
    affiliations: input.principal.affiliations,
    capabilities: input.capabilities,
    allowedActions: input.allowedActions,
    allowedResourceIds: input.allowedResourceIds,
    issuedAt: now,
    expiresAt: input.expiresAt,
    scopeHash: hash("a"),
  };
}

function directDecision(outcome: "ALLOW" | "DENY" | "STEP_UP", reasonCode: AccessDecision["reasonCode"]): AccessDecision {
  return {
    version: 2,
    outcome,
    reasonCode,
    authorityMode: "DIRECT",
    subjectId: "agent:test",
    subjectType: "AGENT",
    actingCredentialId: "credential:test",
    credentialId: "credential:test",
    effectiveScopeHash: hash("a"),
    action: outcome === "STEP_UP" ? "records:export" : "records:read",
    actionSensitivity: outcome === "STEP_UP" ? "SENSITIVE" : "ROUTINE",
    resourceId: outcome === "STEP_UP" ? "dataset:reference-sensitive" : "record:test",
    contextHash: hash("c"),
    policyId: outcome === "STEP_UP" ? "policy:zkya-sensitive-export" : "policy:test",
    policyVersion: hash("b"),
    decidedAt: now,
    ...(outcome === "STEP_UP" ? { requiredApproverCapability: "approval:records-export" } : {}),
  };
}

function receipt(decision: AccessDecision): SignedReceipt {
  if (decision.authorityMode !== "DIRECT" || decision.credentialId === undefined) {
    throw new Error("direct test receipt expected");
  }
  return {
    algorithm: "HMAC-SHA256",
    payload: {
      version: 2,
      authorityMode: "DIRECT",
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
      credentialId: decision.credentialId,
      decision: decision.outcome,
      reasonCode: decision.reasonCode,
      nonce: "receipt-nonce:test",
      decidedAt: now,
      issuedAt: now,
      expiresAt: later,
    },
    signature: "A".repeat(43),
  };
}

function basicClient(getView: () => OnboardingView = () => view()): OnboardingClient {
  return {
    issueCredential: vi.fn(async (input) => ({ credential: credential(input) })),
    revokeCredential: vi.fn(async () => ({ revoked: true })),
    issueDelegation: vi.fn(async () => ({ delegation: {} as CapabilityDelegation })),
    revokeDelegation: vi.fn(async () => ({ revoked: true })),
    evaluate: vi.fn(async () => ({
      logId: "decision-log:test",
      decision: directDecision("ALLOW", "POLICY_ALLOW"),
    })),
    createStepUpRequest: vi.fn(async () => ({ request: {} as StepUpRequest })),
    resolveStepUpRequest: vi.fn(async () => ({ ok: false as const, reasonCode: "STEP_UP_REJECTED" })),
    consumeReceipt: vi.fn(async () => ({ valid: true, reasonCode: "RECEIPT_VALID" })),
    getOnboardingView: vi.fn(async () => getView()),
  };
}

afterEach(cleanup);

test("renders the exact title, persistent limits, accessible controls, and empty initial state", () => {
  render(<App client={basicClient()} />);

  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(
    "zkYA / Know-Your-Agent Onboarding Reference",
  );
  const boundary = screen.getByLabelText("Persistent reference boundary");
  expect(boundary.textContent).toContain("Not real KYC/AML");
  expect(boundary.textContent).toContain("ZK-proof verification");
  expect(boundary.textContent).toContain("production authentication or deployment");
  expect(boundary.textContent).toContain("protected execution");
  expect(boundary.textContent).toContain("autonomous-agent trustworthiness");
  expect(screen.getAllByRole("radio")).toHaveLength(6);
  expect(screen.getByText("No onboarding state retained yet")).toBeTruthy();
});

test("shows loading then direct ALLOW, multiple affiliations, full v2 consume, consumed refresh, and replay rejection", async () => {
  const user = userEvent.setup();
  let release: (() => void) | undefined;
  let consumeCount = 0;
  const allowed = directDecision("ALLOW", "POLICY_ALLOW");
  const signed = receipt(allowed);
  const client = basicClient(() => view({
    principal: {
      id: "agent:reference-direct-reader",
      type: "AGENT",
      affiliations: [
        { organizationId: "organization:ordin-reference", role: "automation-agent" },
        { organizationId: "organization:research-reference", role: "review-participant" },
      ],
    },
    receipt: { status: consumeCount === 0 ? "UNCONSUMED" : "CONSUMED" },
  }));
  client.issueCredential = vi.fn(async (input) => {
    await new Promise<void>((resolve) => { release = resolve; });
    return { credential: credential(input) };
  });
  client.evaluate = vi.fn(async () => ({ logId: "decision-log:test", decision: allowed, receipt: signed }));
  client.consumeReceipt = vi.fn(async () => {
    consumeCount += 1;
    return consumeCount === 1
      ? { valid: true, reasonCode: "RECEIPT_VALID" }
      : { valid: false, reasonCode: "RECEIPT_REPLAYED" };
  });
  render(<App client={client} />);

  await user.click(screen.getByRole("button", { name: "Run reference scenario" }));
  expect(screen.getByRole("button", { name: "Running SDK sequence…" })).toBeTruthy();
  release?.();

  const record = await screen.findByTestId("onboarding-view");
  expect(within(record).getByText("agent:reference-direct-reader")).toBeTruthy();
  expect(within(record).getByText("Affiliations · 2")).toBeTruthy();
  expect(within(record).getByText("HMAC-SHA256")).toBeTruthy();
  expect(within(record).getByText("v2")).toBeTruthy();

  await user.click(within(record).getByRole("button", { name: "Verify & consume full v2 binding" }));
  expect(await screen.findByText("RECEIPT_VALID")).toBeTruthy();
  expect(screen.getAllByText("CONSUMED").length).toBeGreaterThan(0);
  const consumeMock = vi.mocked(client.consumeReceipt);
  expect(consumeMock.mock.calls[0]?.[0].expected).toMatchObject({
    authorityMode: "DIRECT",
    subjectId: allowed.subjectId,
    subjectType: "AGENT",
    actingCredentialId: "credential:test",
    effectiveScopeHash: hash("a"),
    action: "records:read",
    resourceId: "record:test",
    policyId: "policy:test",
    policyVersion: hash("b"),
    credentialId: "credential:test",
    decision: "ALLOW",
    reasonCode: "POLICY_ALLOW",
  });

  await user.click(screen.getByRole("button", { name: "Verify & consume full v2 binding" }));
  expect(await screen.findByText("RECEIPT_REPLAYED")).toBeTruthy();
  expect(screen.getByText("Attempt 2")).toBeTruthy();
  expect(client.getOnboardingView).toHaveBeenCalledTimes(3);
});

test("runs production delegated scenario code and presents AGENT, ORGANIZATION grantor, one affiliation, and exact scopes", async () => {
  const user = userEvent.setup();
  let credentialCount = 0;
  const delegatedDecision: AccessDecision = {
    version: 2,
    outcome: "ALLOW",
    reasonCode: "POLICY_ALLOW",
    authorityMode: "DELEGATED",
    subjectId: "agent:reference-delegate",
    subjectType: "AGENT",
    actingCredentialId: "credential:delegate",
    effectiveScopeHash: hash("d"),
    action: "records:read",
    actionSensitivity: "ROUTINE",
    resourceId: "dataset:reference-alpha",
    contextHash: hash("c"),
    policyId: "policy:zkya-delegated-read",
    policyVersion: hash("b"),
    decidedAt: now,
    grantorId: "organization:reference-grantor",
    grantorType: "ORGANIZATION",
    grantorCredentialId: "credential:grantor",
    delegationId: "delegation:test",
    delegationBindingHash: hash("e"),
  };
  const delegation: CapabilityDelegation = {
    version: 1,
    id: "delegation:test",
    issuerId: "issuer:test",
    grantorCredentialId: "credential:grantor",
    grantorId: "organization:reference-grantor",
    grantorType: "ORGANIZATION",
    delegateId: "agent:reference-delegate",
    delegateType: "AGENT",
    policyId: "policy:zkya-delegated-read",
    policyVersion: hash("b"),
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["dataset:reference-alpha"],
    issuedAt: now,
    expiresAt: later,
    scopeHash: hash("d"),
    delegationBindingHash: hash("e"),
  };
  const client = basicClient(() => view({
    principal: {
      id: "agent:reference-delegate",
      type: "AGENT",
      affiliations: [{ organizationId: "organization:ordin-reference", role: "automation-agent" }],
    },
    authorityMode: "DELEGATED",
    delegatedScope: {
      delegationId: "delegation:test",
      grantorId: "organization:reference-grantor",
      grantorType: "ORGANIZATION",
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: ["dataset:reference-alpha"],
      status: "ACTIVE",
    },
    receipt: { status: "UNCONSUMED" },
  }));
  client.issueCredential = vi.fn(async (input) => ({
    credential: credential(input, ++credentialCount === 1 ? "credential:grantor" : "credential:delegate"),
  }));
  client.issueDelegation = vi.fn(async () => ({ delegation }));
  client.evaluate = vi.fn(async () => ({ logId: "decision-log:test", decision: delegatedDecision }));
  render(<App client={client} />);

  await user.click(screen.getByRole("radio", { name: /Delegated organization scope/ }));
  await user.click(screen.getByRole("button", { name: "Run reference scenario" }));
  const record = await screen.findByTestId("onboarding-view");
  expect(within(record).getAllByText("AGENT").length).toBeGreaterThan(0);
  expect(within(record).getByText("ORGANIZATION")).toBeTruthy();
  expect(within(record).getByText("Affiliations · 1")).toBeTruthy();
  expect(within(record).getAllByText("records:read").length).toBeGreaterThanOrEqual(2);
  expect(within(record).getAllByText("dataset:reference-alpha").length).toBeGreaterThanOrEqual(1);
  expect(client.issueDelegation).toHaveBeenCalledWith(expect.objectContaining({
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["dataset:reference-alpha"],
  }));
});

function stepUpClient(): { client: OnboardingClient; approval: { status: "PENDING" | "APPROVED" | "REJECTED" } } {
  const approval: { status: "PENDING" | "APPROVED" | "REJECTED" } = { status: "PENDING" };
  const decision = directDecision("STEP_UP", "HUMAN_APPROVAL_REQUIRED");
  const request: StepUpRequest = {
    version: 2,
    id: "step-up-request:test",
    authorityMode: "DIRECT",
    subjectId: decision.subjectId,
    subjectType: decision.subjectType,
    actingCredentialId: decision.actingCredentialId,
    effectiveScopeHash: decision.effectiveScopeHash,
    credentialId: "credential:test",
    action: decision.action,
    actionSensitivity: decision.actionSensitivity,
    resourceId: decision.resourceId,
    contextHash: decision.contextHash,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    requiredApproverCapability: "approval:records-export",
    requestedAt: now,
    expiresAt: later,
    status: "PENDING",
  };
  const client = basicClient(() => view({
    principal: { id: "agent:reference-exporter", type: "AGENT", affiliations: [] },
    eligibleActions: [{
      action: "records:export",
      resourceId: "dataset:reference-sensitive",
      status: approval.status === "PENDING" ? "APPROVAL_REQUIRED" : approval.status === "APPROVED" ? "ELIGIBLE" : "INELIGIBLE",
      reasonCode: approval.status === "PENDING" ? "HUMAN_APPROVAL_REQUIRED" : `STEP_UP_${approval.status}`,
    }],
    requiredApproval: { status: approval.status, requestId: request.id },
  }));
  client.evaluate = vi.fn(async () => ({ logId: "decision-log:test", decision }));
  client.createStepUpRequest = vi.fn(async () => ({ request }));
  client.resolveStepUpRequest = vi.fn(async (_id, input) => {
    approval.status = input.resolution === "APPROVE" ? "APPROVED" : "REJECTED";
    return input.resolution === "APPROVE"
      ? { ok: true as const, authorization: {} as never }
      : { ok: false as const, reasonCode: "STEP_UP_REJECTED" };
  });
  return { client, approval };
}

describe("human step-up resolution", () => {
  test.each([
    ["Approve as HUMAN", "APPROVED", "STEP_UP_APPROVED"],
    ["Reject as HUMAN", "REJECTED", "STEP_UP_REJECTED"],
  ] as const)("refreshes the onboarding view after %s", async (button, status, result) => {
    const user = userEvent.setup();
    const { client } = stepUpClient();
    render(<App client={client} />);

    await user.click(screen.getByRole("radio", { name: /Human step-up boundary/ }));
    await user.click(screen.getByRole("button", { name: "Run reference scenario" }));
    expect(await screen.findByText("PENDING")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: button }));
    expect((await screen.findAllByText(result)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(status).length).toBeGreaterThan(0);
    const issueCalls = vi.mocked(client.issueCredential).mock.calls;
    const approverInput = issueCalls.at(-1)?.[0];
    expect(approverInput).toMatchObject({
      principal: { type: "HUMAN" },
      capabilities: ["approval:records-export"],
      allowedActions: ["step-up:resolve"],
      allowedResourceIds: ["dataset:reference-sensitive"],
    });
    expect(client.getOnboardingView).toHaveBeenCalledTimes(2);
  });
});

test("presents zero affiliation plus expired, revoked delegation, scope mismatch, rejected, and consumed states", () => {
  const first = render(<App client={basicClient()} initialView={view({ verificationStatus: "EXPIRED" })} />);
  expect(screen.getByText("No affiliations retained for this principal.")).toBeTruthy();
  expect(screen.getAllByText("EXPIRED").length).toBeGreaterThan(0);

  first.unmount();
  render(<App client={basicClient()} initialView={view({
    verificationStatus: "REVOKED",
    authorityMode: "DELEGATED",
    delegatedScope: {
      delegationId: "delegation:revoked",
      grantorId: "organization:grantor",
      grantorType: "ORGANIZATION",
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: ["record:test"],
      status: "REVOKED",
    },
    eligibleActions: [{
      action: "records:read",
      resourceId: "record:test",
      status: "INELIGIBLE",
      reasonCode: "DELEGATION_REVOKED",
    }],
    requiredApproval: { status: "REJECTED", requestId: "step-up-request:rejected" },
    receipt: { status: "CONSUMED" },
  })} />);
  expect(screen.getAllByText("REVOKED").length).toBeGreaterThan(0);
  expect(screen.getByText("DELEGATION_REVOKED")).toBeTruthy();
  expect(screen.getByText("REJECTED")).toBeTruthy();
  expect(screen.getByText("CONSUMED")).toBeTruthy();
});

test.each([
  [new ZkycTransportError("NETWORK_ERROR"), "Reference API transport is unavailable"],
  [new ZkycTransportError("INVALID_RESPONSE"), "Malformed API response rejected"],
  [new ZkycApiError(400, "INVALID_REQUEST"), "API request failed closed · INVALID_REQUEST · HTTP 400"],
] as const)("renders transport, malformed, and API failures without inferred state", async (failure, expected) => {
  const user = userEvent.setup();
  const client = basicClient();
  client.issueCredential = vi.fn(async () => { throw failure; });
  render(<App client={client} />);

  await user.click(screen.getByRole("button", { name: "Run reference scenario" }));
  expect((await screen.findByRole("alert")).textContent).toContain(expected);
  expect(screen.getByText("No onboarding state retained yet")).toBeTruthy();
});
