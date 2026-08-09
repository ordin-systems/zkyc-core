import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createReferenceApp } from "@ordin/zkyc-core-api-reference";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type FetchLike,
} from "../src/index.js";

const JSON_HEADERS = { "content-type": "application/json" };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

type ResponseFactory = (input: RequestInfo | URL, init?: RequestInit) => Response;

function spyFetch(response: Response | ResponseFactory = jsonResponse({
  ok: true,
  service: "zkyc-core-api-reference",
  version: "0.2.0",
  state: "in-memory-reference-only",
})) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetch: FetchLike = (input, init) => {
    calls.push({ url: String(input), ...(init === undefined ? {} : { init }) });
    return Promise.resolve(typeof response === "function" ? response(input, init) : response.clone());
  };
  return { fetch, calls };
}

const principal = { id: "principal:alice", affiliations: [] };
const credential = {
  version: 1 as const,
  id: "credential:1",
  issuerId: "issuer:reference",
  principalId: principal.id,
  affiliations: [],
  capabilities: ["records:read"],
  issuedAt: "2026-06-01T00:00:00.000Z",
  expiresAt: "2026-06-01T01:00:00.000Z",
};
const policy = {
  id: "policy:allow",
  rules: [{
    action: "records:read",
    actionSensitivity: "ROUTINE" as const,
    requiredCapabilities: ["records:read"],
    requiredAffiliations: [],
    effect: "ALLOW" as const,
  }],
};

function accessDecision(outcome: "ALLOW" | "DENY" | "STEP_UP") {
  return {
    outcome,
    reasonCode: outcome === "ALLOW" ? "POLICY_ALLOW" : outcome === "DENY" ? "POLICY_DENY" : "HUMAN_APPROVAL_REQUIRED",
    subjectId: "principal:alice",
    action: "records:read",
    actionSensitivity: outcome === "STEP_UP" ? "SENSITIVE" : "ROUTINE",
    resourceId: "record:1",
    contextHash: `sha256:${"0".repeat(64)}`,
    policyId: "policy:allow",
    policyVersion: `sha256:${"1".repeat(64)}`,
    credentialId: "credential:1",
    decidedAt: "2026-06-01T00:10:00.000Z",
    ...(outcome === "STEP_UP" ? { requiredApproverCapability: "approval:records-export" } : {}),
  } as const;
}

function routeResponse(input: RequestInfo | URL): Response {
  const path = new URL(String(input)).pathname;
  if (path.endsWith("/health")) return jsonResponse({
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.2.0",
    state: "in-memory-reference-only",
  });
  if (path.endsWith("/revoke")) return jsonResponse({ revoked: true });
  if (path.endsWith("/credentials")) return jsonResponse({ credential });
  if (path.endsWith("/evaluations")) return jsonResponse({ logId: "decision-log:1", decision: accessDecision("ALLOW") });
  if (path.endsWith("/resolve")) return jsonResponse({ ok: false, reasonCode: "STEP_UP_REJECTED" });
  if (path.endsWith("/step-up/requests")) return jsonResponse({
    request: {
      id: "step-up-request:1",
      subjectId: "principal:alice",
      action: "records:read",
      actionSensitivity: "SENSITIVE",
      resourceId: "record:1",
      contextHash: `sha256:${"0".repeat(64)}`,
      policyId: "policy:allow",
      policyVersion: `sha256:${"1".repeat(64)}`,
      credentialId: "credential:1",
      requiredApproverCapability: "approval:records-export",
      requestedAt: "2026-06-01T00:10:00.000Z",
      expiresAt: "2026-06-01T00:20:00.000Z",
      status: "PENDING",
    },
  });
  if (path.endsWith("/step-up/authorizations/consume")) return jsonResponse({ authorized: false });
  if (path.endsWith("/receipts/consume")) return jsonResponse({ valid: false, reasonCode: "RECEIPT_REPLAYED" });
  if (path.endsWith("/decision-log")) return jsonResponse({ referenceOnly: true, entries: [] });
  return jsonResponse({ error: { code: "NOT_FOUND", message: "not found" } }, 404);
}

test("SDK sends the exact method, path, JSON body, and encoded route parameters for every public route", async () => {
  const spy = spyFetch(routeResponse);
  const client = new ZkycReferenceClient({ baseUrl: "https://reference.invalid/api/", fetch: spy.fetch });
  const bodies = {
    issue: { principal, capabilities: ["records:read"], expiresAt: credential.expiresAt },
    revoke: { reason: "test-revocation" },
    evaluation: {
      principal,
      credential,
      action: "records:read",
      resourceId: "record:1",
      actionContext: {},
      policy,
      issueReceipt: false,
    },
    request: { decisionLogId: "decision-log:1", expiresAt: "2026-06-01T00:20:00.000Z" },
    resolution: { resolution: "REJECT" as const, approver: principal, approverCredential: credential },
    authorization: {
      authorization: { id: "authorization:1" },
      subjectId: "principal:alice",
      action: "records:read",
      actionSensitivity: "ROUTINE" as const,
      resourceId: "record:1",
      contextHash: `sha256:${"0".repeat(64)}`,
      policyId: "policy:allow",
      policyVersion: `sha256:${"1".repeat(64)}`,
      credentialId: "credential:1",
    },
    receipt: {
      receipt: { algorithm: "HMAC-SHA256", payload: {}, signature: "x" },
      expected: {
        subjectId: "principal:alice",
        action: "records:read",
        actionSensitivity: "ROUTINE" as const,
        resourceId: "record:1",
        contextHash: `sha256:${"0".repeat(64)}`,
        policyId: "policy:allow",
        policyVersion: `sha256:${"1".repeat(64)}`,
        credentialId: "credential:1",
        decision: "ALLOW" as const,
        reasonCode: "POLICY_ALLOW" as const,
      },
    },
  };

  await client.health();
  await client.issueCredential(bodies.issue);
  await client.revokeCredential("credential:with/slash", bodies.revoke);
  await client.evaluate(bodies.evaluation);
  await client.createStepUpRequest(bodies.request);
  await client.resolveStepUpRequest("step-up:with/slash", bodies.resolution);
  await client.consumeStepUpAuthorization(
    bodies.authorization as unknown as Parameters<ZkycReferenceClient["consumeStepUpAuthorization"]>[0],
  );
  await client.consumeReceipt(
    bodies.receipt as unknown as Parameters<ZkycReferenceClient["consumeReceipt"]>[0],
  );
  await client.getDecisionLog();

  assert.deepEqual(spy.calls.map((call) => [call.init?.method ?? "GET", new URL(call.url).pathname]), [
    ["GET", "/api/health"],
    ["POST", "/api/credentials"],
    ["POST", "/api/credentials/credential%3Awith%2Fslash/revoke"],
    ["POST", "/api/evaluations"],
    ["POST", "/api/step-up/requests"],
    ["POST", "/api/step-up/requests/step-up%3Awith%2Fslash/resolve"],
    ["POST", "/api/step-up/authorizations/consume"],
    ["POST", "/api/receipts/consume"],
    ["GET", "/api/decision-log"],
  ]);
  const postedBodies = spy.calls
    .filter((call) => call.init?.method === "POST")
    .map((call) => JSON.parse(String(call.init?.body)) as unknown);
  assert.deepEqual(postedBodies, [
    bodies.issue,
    bodies.revoke,
    bodies.evaluation,
    bodies.request,
    bodies.resolution,
    bodies.authorization,
    bodies.receipt,
  ]);
});

test("ALLOW, DENY, and STEP_UP remain typed authority outcomes rather than transport exceptions", async () => {
  for (const outcome of ["ALLOW", "DENY", "STEP_UP"] as const) {
    const fetch: FetchLike = () => Promise.resolve(jsonResponse({
      logId: `decision-log:${outcome}`,
      decision: accessDecision(outcome),
    }));
    const client = new ZkycReferenceClient({ baseUrl: "https://reference.invalid", fetch });
    const response = await client.evaluate({
      principal,
      credential,
      action: "records:read",
      resourceId: "record:1",
      actionContext: {},
      policy,
      issueReceipt: false,
    });
    assert.equal(response.decision.outcome, outcome);
  }
});

test("JSON API failures throw ZkycApiError and preserve a safe status/code", async () => {
  const fetch: FetchLike = () => Promise.resolve(jsonResponse({
    error: { code: "INVALID_REQUEST", message: "request body is invalid" },
  }, 400));
  const client = new ZkycReferenceClient({ baseUrl: "https://reference.invalid", fetch });
  await assert.rejects(
    () => client.health(),
    (error: unknown) => {
      assert.ok(error instanceof ZkycApiError);
      assert.equal(error.status, 400);
      assert.equal(error.code, "INVALID_REQUEST");
      return true;
    },
  );
});

test("non-JSON responses and network failures throw predictable ZkycTransportError values", async () => {
  const htmlClient = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: () => Promise.resolve(new Response("<html>no</html>", {
      status: 502,
      headers: { "content-type": "text/html" },
    })),
  });
  await assert.rejects(
    () => htmlClient.health(),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
  );

  const networkClient = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: () => Promise.reject(new Error("socket detail must not leak")),
  });
  await assert.rejects(
    () => networkClient.health(),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "NETWORK_ERROR",
  );
});

test("malformed successful and error schemas fail with INVALID_RESPONSE", async () => {
  const malformedHealth = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: spyFetch(jsonResponse({ ok: false, service: 17 })).fetch,
  });
  await assert.rejects(
    () => malformedHealth.health(),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
  );

  const malformedCredentials = [
    { ...credential, id: 17 },
    { ...credential, issuerId: null },
    { ...credential, principalId: [] },
    { ...credential, affiliations: "not-an-array" },
    { ...credential, affiliations: [{ organizationId: 17, role: "reviewer" }] },
    { ...credential, capabilities: [17] },
    { ...credential, issuedAt: "not-a-time" },
    { ...credential, expiresAt: false },
    { ...credential, expiresAt: credential.issuedAt },
  ];
  for (const malformedCredential of malformedCredentials) {
    const client = new ZkycReferenceClient({
      baseUrl: "https://reference.invalid",
      fetch: spyFetch(jsonResponse({ credential: malformedCredential }, 201)).fetch,
    });
    await assert.rejects(
      () => client.issueCredential({
        principal,
        capabilities: [],
        expiresAt: "2026-06-01T01:00:00.000Z",
      }),
      (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
    );
  }

  const malformedDecision = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: spyFetch(jsonResponse({
      logId: "decision-log:bad",
      decision: { ...accessDecision("ALLOW"), outcome: "MAYBE" },
    })).fetch,
  });
  await assert.rejects(
    () => malformedDecision.evaluate({
      principal,
      credential,
      action: "records:read",
      resourceId: "record:1",
      actionContext: {},
      policy,
      issueReceipt: false,
    }),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
  );

  const malformedError = new ZkycReferenceClient({
    baseUrl: "https://reference.invalid",
    fetch: spyFetch(jsonResponse({ error: { code: 17, message: "bad" } }, 400)).fetch,
  });
  await assert.rejects(
    () => malformedError.health(),
    (error: unknown) => error instanceof ZkycTransportError && error.code === "INVALID_RESPONSE",
  );
});

test("receipt consume contract works through the SDK against Hono app.request", async () => {
  let counter = 0;
  const app = createReferenceApp({
    clock: () => "2026-06-01T00:10:00.000Z",
    idFactory: (kind) => `${kind}:${++counter}`,
    receiptHmacKey: new TextEncoder().encode("0123456789abcdef0123456789abcdef"),
    issuerId: "issuer:sdk-contract",
  });
  const fetch: FetchLike = (input, init) => app.request(String(input), init);
  const client = new ZkycReferenceClient({ baseUrl: "https://reference.test", fetch });

  const issued = await client.issueCredential({
    principal,
    capabilities: ["records:read"],
    expiresAt: "2026-06-01T01:00:00.000Z",
  });
  const evaluated = await client.evaluate({
    principal,
    credential: issued.credential,
    action: "records:read",
    resourceId: "record:sdk-contract",
    actionContext: { purpose: "contract" },
    policy,
    issueReceipt: true,
    receiptExpiresAt: "2026-06-01T00:20:00.000Z",
  });
  assert.equal(evaluated.decision.outcome, "ALLOW");
  assert.ok(evaluated.receipt);
  assert.ok(evaluated.decision.credentialId);
  const consumed = await client.consumeReceipt({
    receipt: evaluated.receipt,
    expected: {
      subjectId: evaluated.decision.subjectId,
      action: evaluated.decision.action,
      actionSensitivity: evaluated.decision.actionSensitivity,
      resourceId: evaluated.decision.resourceId,
      contextHash: evaluated.decision.contextHash,
      policyId: evaluated.decision.policyId,
      policyVersion: evaluated.decision.policyVersion,
      credentialId: evaluated.decision.credentialId,
      decision: evaluated.decision.outcome,
      reasonCode: evaluated.decision.reasonCode,
    },
  });
  assert.deepEqual(consumed, { valid: true, reasonCode: "RECEIPT_VALID" });
});

test("checked-in full-stack fixture is parsed and exercised through SDK and Hono contracts", async () => {
  const fixtureUrl = new URL("../../../../fixtures/full-stack-reference-cases.json", import.meta.url);
  const fixtures = JSON.parse(await readFile(fixtureUrl, "utf8")) as Array<{
    credential: Parameters<ZkycReferenceClient["issueCredential"]>[0];
    evaluation: Omit<Parameters<ZkycReferenceClient["evaluate"]>[0], "principal" | "credential">;
    expected: { outcome: string; reasonCode: string; hasReceipt: boolean };
  }>;
  let counter = 0;
  const app = createReferenceApp({
    clock: () => "2026-06-01T00:10:00.000Z",
    idFactory: (kind) => `${kind}:${++counter}`,
    receiptHmacKey: new TextEncoder().encode("abcdef0123456789abcdef0123456789"),
  });
  const client = new ZkycReferenceClient({
    baseUrl: "https://fixture.test",
    fetch: (input, init) => app.request(String(input), init),
  });
  for (const fixture of fixtures) {
    const issued = await client.issueCredential(fixture.credential);
    const evaluated = await client.evaluate({
      principal: fixture.credential.principal,
      credential: issued.credential,
      ...fixture.evaluation,
    });
    assert.equal(evaluated.decision.outcome, fixture.expected.outcome);
    assert.equal(evaluated.decision.reasonCode, fixture.expected.reasonCode);
    assert.equal(evaluated.receipt !== undefined, fixture.expected.hasReceipt);
  }
});

test("SDK resolves a browser-relative base URL against the current page", async () => {
  const originalLocation = Reflect.getOwnPropertyDescriptor(globalThis, "location");
  Reflect.defineProperty(globalThis, "location", {
    configurable: true,
    value: new URL("https://reviewer.invalid/cockpit"),
  });
  try {
    const spy = spyFetch(jsonResponse({
      ok: true,
      service: "zkyc-core-api-reference",
      version: "0.2.0",
      state: "in-memory-reference-only",
    }));
    const client = new ZkycReferenceClient({ baseUrl: "/api/", fetch: spy.fetch });
    await client.health();
    assert.equal(spy.calls[0]?.url, "https://reviewer.invalid/api/health");
  } finally {
    if (originalLocation === undefined) Reflect.deleteProperty(globalThis, "location");
    else Reflect.defineProperty(globalThis, "location", originalLocation);
  }
});
