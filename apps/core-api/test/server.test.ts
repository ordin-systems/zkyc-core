import assert from "node:assert/strict";
import test from "node:test";
import { ActionSensitivity, PrincipalType, type Credential } from "@ordin/zkyc-core-reference";
import { createReferenceApp } from "../src/app.js";
import { startLoopbackReferenceServer } from "../src/server-runtime.js";

const START = "2026-06-01T00:10:00.000Z";
const EXPIRY = "2026-06-01T01:00:00.000Z";
const RESOURCE = "record:server-smoke";
const SERVER_POLICY = {
  id: "policy:server-smoke",
  rules: [{
    action: "records:read",
    actionSensitivity: ActionSensitivity.ROUTINE,
    requiredCapabilities: ["records:read"],
    requiredAffiliations: [],
    effect: "ALLOW" as const,
  }],
};

async function postJson(baseUrl: string, path: string, body: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() as unknown };
}

test("compiled reference listener binds loopback and serves health plus retained onboarding", async () => {
  const counters = new Map<string, number>();
  const app = createReferenceApp({
    clock: () => START,
    idFactory: (kind) => {
      const next = (counters.get(kind) ?? 0) + 1;
      counters.set(kind, next);
      return `${kind}:server-${next}`;
    },
    receiptHmacKey: new TextEncoder().encode("0123456789abcdef0123456789abcdef"),
    trustedPolicies: [SERVER_POLICY],
    issuerId: "issuer:server-test",
  });

  let server: ReturnType<typeof startLoopbackReferenceServer> | undefined;
  const info = await new Promise<{ readonly port: number }>((resolve) => {
    server = startLoopbackReferenceServer(app.fetch, 0, resolve);
  });

  assert.ok(server);
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    assert.equal(address.address, "127.0.0.1");
    const baseUrl = `http://127.0.0.1:${info.port}`;

    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), {
      ok: true,
      service: "zkyc-core-api-reference",
      version: "0.3.0",
      state: "in-memory-reference-only",
    });

    const issued = await postJson(baseUrl, "/credentials", {
      principal: {
        id: "principal:server-smoke",
        type: PrincipalType.AGENT,
        affiliations: [],
      },
      capabilities: ["records:read"],
      allowedActions: ["records:read"],
      allowedResourceIds: [RESOURCE],
      expiresAt: EXPIRY,
    });
    assert.equal(issued.response.status, 201);
    const credential = (issued.body as { credential: Credential }).credential;

    const evaluated = await postJson(baseUrl, "/evaluations", {
      authorityMode: "DIRECT",
      principal: {
        id: credential.principalId,
        type: credential.principalType,
        affiliations: credential.affiliations,
      },
      credential,
      action: "records:read",
      resourceId: RESOURCE,
      actionContext: { source: "real-http-smoke" },
      policy: SERVER_POLICY,
      issueReceipt: false,
    });
    assert.equal(evaluated.response.status, 200);
    const logId = (evaluated.body as { logId: string }).logId;

    const onboarding = await fetch(
      `${baseUrl}/zkya/onboarding-views/${encodeURIComponent(logId)}`,
    );
    assert.equal(onboarding.status, 200);
    assert.deepEqual(await onboarding.json(), {
      version: 1,
      referenceOnly: true,
      decisionLogId: logId,
      verificationStatus: "ACTIVE",
      principal: {
        id: "principal:server-smoke",
        type: PrincipalType.AGENT,
        affiliations: [],
      },
      authorityMode: "DIRECT",
      delegatedScope: null,
      eligibleActions: [{
        action: "records:read",
        resourceId: RESOURCE,
        status: "ELIGIBLE",
        reasonCode: "POLICY_ALLOW",
      }],
      requiredApproval: { status: "NOT_REQUIRED" },
      receipt: {
        consumptionStatus: "NOT_ISSUED",
        lastAttempt: { outcome: "NONE" },
      },
      policyId: "policy:server-smoke",
      policyVersion: (evaluated.body as { decision: { policyVersion: string } }).decision
        .policyVersion,
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => error === undefined ? resolve() : reject(error));
    });
  }
});
