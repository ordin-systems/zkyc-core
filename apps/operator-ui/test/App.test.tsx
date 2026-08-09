import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test } from "vitest";
import { ZkycTransportError } from "@ordin/zkyc-sdk-reference";
import { App, type CockpitClient } from "../src/App.js";

afterEach(cleanup);

function referenceClient(): CockpitClient {
  let credentialNumber = 0;
  let decisionNumber = 0;
  let stepConsumeCount = 0;

  return {
    issueCredential: async (input) => ({
      credential: {
        version: 1,
        id: `credential:ui-${++credentialNumber}`,
        issuerId: "issuer:ui-test",
        principalId: input.principal.id,
        affiliations: input.principal.affiliations,
        capabilities: input.capabilities,
        issuedAt: "2026-08-09T00:00:00.000Z",
        expiresAt: input.expiresAt,
      },
    }),
    evaluate: async (input) => {
      const isStepUp = input.action === "records:export";
      const outcome = isStepUp ? "STEP_UP" : input.action === "records:delete" ? "DENY" : "ALLOW";
      const reasonCode = isStepUp
        ? "HUMAN_APPROVAL_REQUIRED"
        : outcome === "DENY"
          ? "POLICY_DENY"
          : "POLICY_ALLOW";
      const decision = {
        version: 1,
        subjectId: input.principal.id,
        credentialId: input.credential?.id ?? "credential:missing",
        action: input.action,
        actionSensitivity: isStepUp ? "SENSITIVE" : outcome === "DENY" ? "CRITICAL" : "ROUTINE",
        resourceId: input.resourceId,
        contextHash: `sha256:${"1".repeat(64)}`,
        policyId: input.policy.id,
        policyVersion: `sha256:${"2".repeat(64)}`,
        outcome,
        reasonCode,
        decidedAt: "2026-08-09T00:00:00.000Z",
        ...(isStepUp ? { requiredApproverCapability: "approval:records-export" } : {}),
      } as const;
      const receipt = outcome === "ALLOW"
        ? {
            algorithm: "HMAC-SHA256" as const,
            payload: {
              ...decision,
              decision: "ALLOW" as const,
              reasonCode: "POLICY_ALLOW" as const,
              nonce: "receipt-nonce:ui-1",
              issuedAt: decision.decidedAt,
              expiresAt: "2026-08-09T01:00:00.000Z",
            },
            signature: "reference-signature",
          }
        : undefined;
      return {
        logId: `decision-log:ui-${++decisionNumber}`,
        decision,
        ...(receipt === undefined ? {} : { receipt }),
      } as Awaited<ReturnType<CockpitClient["evaluate"]>>;
    },
    createStepUpRequest: async () => ({
      request: {
        version: 1,
        id: "step-up-request:ui-1",
        subjectId: "principal:reference-exporter",
        credentialId: "credential:ui-2",
        action: "records:export",
        actionSensitivity: "SENSITIVE",
        resourceId: "dataset:reference-7",
        contextHash: `sha256:${"1".repeat(64)}`,
        policyId: "policy:reference-step-up",
        policyVersion: `sha256:${"2".repeat(64)}`,
        reasonCode: "HUMAN_APPROVAL_REQUIRED",
        requiredApproverCapability: "approval:records-export",
        requestedAt: "2026-08-09T00:00:00.000Z",
        expiresAt: "2026-08-09T01:00:00.000Z",
        status: "PENDING",
      },
    }) as Awaited<ReturnType<CockpitClient["createStepUpRequest"]>>,
    resolveStepUpRequest: async (_id, input) => input.resolution === "APPROVE"
      ? ({
          ok: true,
          authorization: {
            version: 1,
            id: "step-up-authorization:ui-1",
            requestId: "step-up-request:ui-1",
            subjectId: "principal:reference-exporter",
            credentialId: "credential:ui-2",
            action: "records:export",
            actionSensitivity: "SENSITIVE",
            resourceId: "dataset:reference-7",
            contextHash: `sha256:${"1".repeat(64)}`,
            policyId: "policy:reference-step-up",
            policyVersion: `sha256:${"2".repeat(64)}`,
            approvedBy: input.approver.id,
            issuedAt: "2026-08-09T00:01:00.000Z",
            expiresAt: "2026-08-09T01:00:00.000Z",
          },
        } as Awaited<ReturnType<CockpitClient["resolveStepUpRequest"]>>)
      : ({ ok: false, reasonCode: "STEP_UP_REJECTED" }),
    consumeStepUpAuthorization: async () => ({ authorized: ++stepConsumeCount === 1 }),
    consumeReceipt: async () => ({ valid: true, reasonCode: "RECEIPT_CONSUMED" }),
    getDecisionLog: async () => ({ referenceOnly: true, entries: [] }),
  };
}

test("cockpit renders and drives ALLOW plus STEP_UP one-time authority states", async () => {
  const user = userEvent.setup();
  render(<App client={referenceClient()} />);

  expect(screen.getByText("REFERENCE ONLY")).toBeTruthy();
  expect(screen.getByText(/Not KYC, ZK verification/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /protected action/i })).toBeNull();

  await user.click(screen.getByRole("button", { name: "Evaluate authority" }));
  expect(await screen.findByText("POLICY_ALLOW")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Verify and consume once" }));
  expect(await screen.findByText("RECEIPT_CONSUMED")).toBeTruthy();

  await user.click(screen.getByRole("radio", { name: /STEP_UP.*Sensitive export/ }));
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

test("manual decision-log refresh catches and renders transport failures", async () => {
  const user = userEvent.setup();
  const client: CockpitClient = {
    ...referenceClient(),
    getDecisionLog: async () => {
      throw new ZkycTransportError("NETWORK_ERROR");
    },
  };
  render(<App client={client} />);
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText("Transport unavailable: NETWORK_ERROR")).toBeTruthy();
});
