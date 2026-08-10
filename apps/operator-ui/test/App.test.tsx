import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test } from "vitest";
import {
  ZkycTransportError,
  type AccessDecision,
  type BoundAccessDecision,
  type CapabilityDelegation,
  type Credential,
  type DecisionOutcome,
  type ReasonCode,
  type SignedReceipt,
  type StepUpAuthorization,
  type StepUpRequest,
} from "@ordin/zkyc-sdk-reference";
import { App, type CockpitClient } from "../src/App.js";

const hash = (character: string) => `sha256:${character.repeat(64)}`;
const now = "2026-08-09T00:00:00.000Z";
const later = "2026-08-09T01:00:00.000Z";

interface ReferenceClientState {
  readonly client: CockpitClient;
  readonly delegatedCalls: { count: number };
}

function isBoundDecision(decision: AccessDecision): decision is BoundAccessDecision {
  return decision.actingCredentialId !== undefined && decision.effectiveScopeHash !== undefined;
}

function receiptFor(decision: AccessDecision): SignedReceipt {
  if (!isBoundDecision(decision)) throw new Error("receipt decision is missing authority bindings");
  const common = {
    version: 2 as const,
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
    nonce: "receipt-nonce:ui-1",
    decidedAt: decision.decidedAt,
    issuedAt: decision.decidedAt,
    expiresAt: later,
    ...(decision.requiredApproverCapability === undefined
      ? {}
      : { requiredApproverCapability: decision.requiredApproverCapability }),
  };
  const payload = decision.authorityMode === "DIRECT"
    ? {
        ...common,
        authorityMode: "DIRECT" as const,
        credentialId: decision.credentialId ?? decision.actingCredentialId,
      }
    : {
        ...common,
        authorityMode: "DELEGATED" as const,
        grantorId: decision.grantorId,
        grantorType: decision.grantorType,
        grantorCredentialId: decision.grantorCredentialId,
        delegationId: decision.delegationId,
        delegationBindingHash: decision.delegationBindingHash,
      };
  return { algorithm: "HMAC-SHA256", payload, signature: "A".repeat(43) };
}

function referenceClient(): ReferenceClientState {
  let credentialNumber = 0;
  let decisionNumber = 0;
  let stepConsumeCount = 0;
  const delegatedCalls = { count: 0 };

  const client: CockpitClient = {
    issueCredential: async (input) => ({
      credential: {
        version: 2,
        id: `credential:ui-${++credentialNumber}`,
        issuerId: "issuer:ui-test",
        principalId: input.principal.id,
        principalType: input.principal.type,
        affiliations: input.principal.affiliations,
        capabilities: input.capabilities,
        allowedActions: input.allowedActions,
        allowedResourceIds: input.allowedResourceIds,
        issuedAt: now,
        expiresAt: input.expiresAt,
        scopeHash: hash("a"),
      },
    }),
    issueDelegation: async (input) => {
      delegatedCalls.count += 1;
      const delegation: CapabilityDelegation = {
        version: 1,
        id: "delegation:ui-1",
        issuerId: "issuer:ui-test",
        grantorCredentialId: input.grantorCredential.id,
        grantorId: input.grantor.id,
        grantorType: input.grantor.type,
        delegateId: input.delegate.id,
        delegateType: input.delegate.type,
        policyId: input.policy.id,
        policyVersion: hash("b"),
        capabilities: input.capabilities,
        allowedActions: input.allowedActions,
        allowedResourceIds: input.allowedResourceIds,
        issuedAt: now,
        expiresAt: input.expiresAt,
        scopeHash: hash("c"),
        delegationBindingHash: hash("d"),
      };
      return { delegation };
    },
    evaluate: async (input) => {
      const isStepUp = input.action === "records:export";
      const outcome: DecisionOutcome = isStepUp
        ? "STEP_UP"
        : input.action === "records:delete" ? "DENY" : "ALLOW";
      const reasonCode: ReasonCode = isStepUp
        ? "HUMAN_APPROVAL_REQUIRED"
        : outcome === "DENY"
          ? "POLICY_DENY"
          : "POLICY_ALLOW";
      const common = {
        version: 2 as const,
        outcome,
        reasonCode,
        authorityMode: input.authorityMode,
        subjectId: input.principal.id,
        subjectType: input.principal.type,
        actingCredentialId: input.authorityMode === "DIRECT"
          ? input.credential?.id ?? "credential:missing"
          : input.delegateIdentityCredential.id,
        effectiveScopeHash: input.authorityMode === "DIRECT"
          ? input.credential?.scopeHash ?? hash("0")
          : input.delegation.scopeHash,
        action: input.action,
        actionSensitivity: isStepUp ? "SENSITIVE" as const : outcome === "DENY" ? "CRITICAL" as const : "ROUTINE" as const,
        resourceId: input.resourceId,
        contextHash: hash("1"),
        policyId: input.policy.id,
        policyVersion: hash("2"),
        decidedAt: now,
        ...(isStepUp ? { requiredApproverCapability: "approval:records-export" } : {}),
      };
      const decision: AccessDecision = input.authorityMode === "DIRECT"
        ? {
            ...common,
            authorityMode: "DIRECT",
            credentialId: input.credential?.id ?? "credential:missing",
          }
        : {
            ...common,
            authorityMode: "DELEGATED",
            grantorId: input.grantorCredential.principalId,
            grantorType: input.grantorCredential.principalType,
            grantorCredentialId: input.grantorCredential.id,
            delegationId: input.delegation.id,
            delegationBindingHash: input.delegation.delegationBindingHash,
          };
      return {
        logId: `decision-log:ui-${++decisionNumber}`,
        decision,
        ...(outcome === "ALLOW" ? { receipt: receiptFor(decision) } : {}),
      };
    },
    createStepUpRequest: async (input) => {
      const request: StepUpRequest = {
        version: 2,
        id: "step-up-request:ui-1",
        authorityMode: "DIRECT",
        subjectId: "principal:reference-exporter",
        subjectType: "AGENT",
        actingCredentialId: "credential:ui-step",
        effectiveScopeHash: hash("a"),
        credentialId: "credential:ui-step",
        action: "records:export",
        actionSensitivity: "SENSITIVE",
        resourceId: "dataset:reference-7",
        contextHash: hash("1"),
        policyId: "policy:reference-step-up",
        policyVersion: hash("2"),
        requiredApproverCapability: "approval:records-export",
        requestedAt: now,
        expiresAt: later,
        status: "PENDING",
      };
      return { decisionLogId: input.decisionLogId, request };
    },
    resolveStepUpRequest: async (_id, input) => {
      if (input.resolution === "REJECT") return { ok: false, reasonCode: "STEP_UP_REJECTED" };
      const authorization: StepUpAuthorization = {
        version: 2,
        id: "step-up-authorization:ui-1",
        requestId: "step-up-request:ui-1",
        authorityMode: "DIRECT",
        subjectId: "principal:reference-exporter",
        subjectType: "AGENT",
        actingCredentialId: "credential:ui-step",
        effectiveScopeHash: hash("a"),
        credentialId: "credential:ui-step",
        action: "records:export",
        actionSensitivity: "SENSITIVE",
        resourceId: "dataset:reference-7",
        contextHash: hash("1"),
        policyId: "policy:reference-step-up",
        policyVersion: hash("2"),
        requiredApproverCapability: "approval:records-export",
        approvedBy: input.approver.id,
        approvedByType: input.approver.type,
        approverCredentialId: input.approverCredential.id,
        issuedAt: now,
        expiresAt: later,
      };
      return { ok: true, authorization };
    },
    consumeStepUpAuthorization: async () => ({ authorized: ++stepConsumeCount === 1 }),
    consumeReceipt: async () => ({ valid: true, reasonCode: "RECEIPT_CONSUMED" }),
    getDecisionLog: async () => ({ referenceOnly: true, entries: [] }),
  };
  return { client, delegatedCalls };
}

afterEach(cleanup);

test("cockpit renders v0.3 direct scope and drives receipt plus one-time step-up authority", async () => {
  const user = userEvent.setup();
  const { client } = referenceClient();
  render(<App client={client} />);

  expect(screen.getByText("REFERENCE ONLY")).toBeTruthy();
  expect(screen.getByText(/Not KYC, ZK verification/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /protected action/i })).toBeNull();

  await user.click(screen.getByRole("button", { name: "Evaluate authority" }));
  expect(await screen.findByText("POLICY_ALLOW")).toBeTruthy();
  expect(screen.getAllByText("AGENT").length).toBeGreaterThan(0);
  expect(screen.getByText("DIRECT")).toBeTruthy();
  expect(screen.getByLabelText("Bound authority scope").textContent).toContain("record:reference-7");
  await user.click(screen.getByRole("button", { name: "Verify and consume once" }));
  expect(await screen.findByText("RECEIPT_CONSUMED")).toBeTruthy();

  await user.click(screen.getByRole("radio", { name: /Sensitive export/ }));
  await user.click(screen.getByRole("button", { name: "Evaluate authority" }));
  expect(await screen.findByText("HUMAN_APPROVAL_REQUIRED")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Approve" }));
  expect(await screen.findByText("STEP_UP_APPROVED")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Verify and consume once" }));
  expect(await screen.findByText("STEP_UP_AUTHORIZATION_CONSUMED")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Verify and consume once" }));
  expect(await screen.findByText("STEP_UP_AUTHORIZATION_REJECTED")).toBeTruthy();

  await user.click(screen.getByRole("button", { name: "Evaluate authority" }));
  await user.click(screen.getByRole("button", { name: "Reject" }));
  expect(await screen.findByText("STEP_UP_REJECTED")).toBeTruthy();
});

test("cockpit executes and displays one-hop delegated binding without grantor affiliation transfer", async () => {
  const user = userEvent.setup();
  const { client, delegatedCalls } = referenceClient();
  render(<App client={client} />);

  await user.click(screen.getByRole("radio", { name: /Delegated routine read/ }));
  await user.click(screen.getByRole("button", { name: "Evaluate authority" }));
  expect(await screen.findByText("DELEGATED")).toBeTruthy();
  const binding = screen.getByLabelText("Delegation binding");
  expect(binding.textContent).toContain("organization:reference-grantor / ORGANIZATION");
  expect(binding.textContent).toContain("delegation:ui-1");
  expect(binding.textContent).toContain(hash("d"));
  const scope = screen.getByLabelText("Bound authority scope");
  expect(scope.textContent).toContain("Capabilities: records:read");
  expect(scope.textContent).toContain("Actions: records:read");
  expect(scope.textContent).toContain("Resources: record:reference-delegated");
  expect(delegatedCalls.count).toBe(1);
});

test("manual decision-log refresh catches and renders transport failures", async () => {
  const user = userEvent.setup();
  const { client: base } = referenceClient();
  const client: CockpitClient = {
    ...base,
    getDecisionLog: async () => {
      throw new ZkycTransportError("NETWORK_ERROR");
    },
  };
  render(<App client={client} />);
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText("Transport unavailable: NETWORK_ERROR")).toBeTruthy();
});
