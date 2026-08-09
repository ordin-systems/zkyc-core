import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ActionSensitivity,
  type AccessDecision,
  type Credential,
  type ReceiptExpectedBinding,
  type SignedReceipt,
  type StepUpAuthorization,
} from "@ordin/zkyc-core-reference";
import { createReferenceApp } from "../src/app.js";

const TEST_KEY = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
const START = "2026-06-01T00:10:00.000Z";
const EXPIRY = "2026-06-01T01:00:00.000Z";
const RECEIPT_EXPIRY = "2026-06-01T00:20:00.000Z";
const MEMBER = { organizationId: "organization:fixture", role: "member" } as const;

type JsonRecord = Record<string, unknown>;

interface FixtureCase {
  readonly name: string;
  readonly credential: {
    readonly principal: JsonRecord;
    readonly capabilities: readonly string[];
    readonly expiresAt: string;
  };
  readonly evaluation: {
    readonly action: string;
    readonly resourceId: string;
    readonly actionContext: JsonRecord;
    readonly policy: JsonRecord;
    readonly issueReceipt: boolean;
    readonly receiptExpiresAt: string;
  };
  readonly expected: {
    readonly outcome: string;
    readonly reasonCode: string;
    readonly hasReceipt: boolean;
  };
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
  const requestBody = options.rawBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body));
  const init: RequestInit = {
    method: options.method ?? "GET",
    ...(requestBody === undefined
      ? {}
      : { headers: { "content-type": options.contentType ?? "application/json" }, body: requestBody }),
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

async function issueCredential(
  app: ReturnType<typeof createReferenceApp>,
  input: {
    principalId?: string;
    affiliations?: readonly typeof MEMBER[];
    capabilities?: readonly string[];
    expiresAt?: string;
  } = {},
): Promise<Credential> {
  const result = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: {
        id: input.principalId ?? "principal:alice",
        affiliations: input.affiliations ?? [MEMBER],
      },
      capabilities: input.capabilities ?? ["records:read", "records:export"],
      expiresAt: input.expiresAt ?? EXPIRY,
    },
  });
  assert.equal(result.response.status, 201);
  return (result.body as { credential: Credential }).credential;
}

function policy(effect: "ALLOW" | "DENY" | "STEP_UP", action = "records:read") {
  return {
    id: `policy:${effect.toLowerCase()}`,
    rules: [{
      action,
      actionSensitivity: effect === "STEP_UP" ? ActionSensitivity.SENSITIVE : ActionSensitivity.ROUTINE,
      requiredCapabilities: [action],
      requiredAffiliations: [MEMBER],
      effect,
      ...(effect === "STEP_UP" ? { approverCapability: "approval:records-export" } : {}),
    }],
  };
}

async function evaluate(
  app: ReturnType<typeof createReferenceApp>,
  credential: Credential,
  input: {
    effect?: "ALLOW" | "DENY" | "STEP_UP";
    action?: string;
    resourceId?: string;
    issueReceipt?: boolean;
  } = {},
) {
  const effect = input.effect ?? "ALLOW";
  const action = input.action ?? (effect === "STEP_UP" ? "records:export" : "records:read");
  return requestJson(app, "/evaluations", {
    method: "POST",
    body: {
      principal: { id: credential.principalId, affiliations: credential.affiliations },
      credential,
      action,
      resourceId: input.resourceId ?? "record:customer-7",
      actionContext: { fields: ["status"], purpose: "review" },
      policy: policy(effect, action),
      issueReceipt: input.issueReceipt ?? true,
      ...((input.issueReceipt ?? true) ? { receiptExpiresAt: RECEIPT_EXPIRY } : {}),
    },
  });
}

function expectedBinding(decision: AccessDecision): ReceiptExpectedBinding {
  assert.ok(decision.credentialId);
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

test("health identifies the sanitized reference-only adapter", async () => {
  const { app } = harness();
  const result = await requestJson(app, "/health");
  assert.equal(result.response.status, 200);
  assert.deepEqual(result.body, {
    ok: true,
    service: "zkyc-core-api-reference",
    version: "0.2.0",
    state: "in-memory-reference-only",
  });
});

test("deterministic full-stack fixtures execute through the API and only ALLOW receives a receipt", async () => {
  const fixturesUrl = new URL("../../../../fixtures/full-stack-reference-cases.json", import.meta.url);
  const fixtures = JSON.parse(await readFile(fixturesUrl, "utf8")) as FixtureCase[];
  for (const fixture of fixtures) {
    const { app } = harness();
    const issued = await requestJson(app, "/credentials", {
      method: "POST",
      body: fixture.credential,
    });
    assert.equal(issued.response.status, 201, fixture.name);
    const credential = (issued.body as { credential: Credential }).credential;
    const evaluated = await requestJson(app, "/evaluations", {
      method: "POST",
      body: {
        principal: fixture.credential.principal,
        credential,
        ...fixture.evaluation,
      },
    });
    assert.equal(evaluated.response.status, 200, fixture.name);
    const output = evaluated.body as { decision: AccessDecision; receipt?: SignedReceipt };
    assert.equal(output.decision.outcome, fixture.expected.outcome, fixture.name);
    assert.equal(output.decision.reasonCode, fixture.expected.reasonCode, fixture.name);
    assert.equal(output.receipt !== undefined, fixture.expected.hasReceipt, fixture.name);
  }
});

test("receipt consume preserves every binding, detects tampering, and rejects sequential replay", async () => {
  const { app } = harness();
  const credential = await issueCredential(app);
  const evaluated = await evaluate(app, credential);
  assert.equal(evaluated.response.status, 200);
  const output = evaluated.body as { decision: AccessDecision; receipt: SignedReceipt };
  assert.equal(output.decision.outcome, "ALLOW");
  const expected = expectedBinding(output.decision);

  const mismatch = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected: { ...expected, resourceId: "record:other" } },
  });
  assert.deepEqual(mismatch.body, { valid: false, reasonCode: "RECEIPT_BINDING_MISMATCH" });

  const tampered = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: {
      receipt: { ...output.receipt, payload: { ...output.receipt.payload, action: "records:write" } },
      expected,
    },
  });
  assert.deepEqual(tampered.body, { valid: false, reasonCode: "RECEIPT_SIGNATURE_INVALID" });

  const first = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected },
  });
  assert.deepEqual(first.body, { valid: true, reasonCode: "RECEIPT_VALID" });
  const replay = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected },
  });
  assert.deepEqual(replay.body, { valid: false, reasonCode: "RECEIPT_REPLAYED" });
});

test("receipt consumption requires a complete expected binding", async () => {
  const { app } = harness();
  const credential = await issueCredential(app);
  const evaluated = await evaluate(app, credential);
  const output = evaluated.body as { decision: AccessDecision; receipt: SignedReceipt };
  const { reasonCode: _removed, ...incomplete } = expectedBinding(output.decision);
  const result = await requestJson(app, "/receipts/consume", {
    method: "POST",
    body: { receipt: output.receipt, expected: incomplete },
  });
  assert.equal(result.response.status, 400);
  assert.equal((result.body as { error: { code: string } }).error.code, "INVALID_REQUEST");
});

test("step-up can be created from a logged decision, approved, and consumed once", async () => {
  const { app, setNow } = harness();
  const subjectCredential = await issueCredential(app, { capabilities: ["records:export"] });
  const evaluated = await evaluate(app, subjectCredential, { effect: "STEP_UP", action: "records:export" });
  const evaluation = evaluated.body as { logId: string; decision: AccessDecision; receipt?: SignedReceipt };
  assert.equal(evaluation.decision.outcome, "STEP_UP");
  assert.equal(evaluation.receipt, undefined);

  const created = await requestJson(app, "/step-up/requests", {
    method: "POST",
    body: { decisionLogId: evaluation.logId, expiresAt: RECEIPT_EXPIRY },
  });
  assert.equal(created.response.status, 201);
  const request = (created.body as { request: { id: string } }).request;

  const approverCredential = await issueCredential(app, {
    principalId: "principal:bob",
    capabilities: ["approval:records-export"],
  });
  setNow("2026-06-01T00:11:00.000Z");
  const resolved = await requestJson(app, `/step-up/requests/${encodeURIComponent(request.id)}/resolve`, {
    method: "POST",
    body: {
      resolution: "APPROVE",
      approver: { id: approverCredential.principalId, affiliations: approverCredential.affiliations },
      approverCredential,
    },
  });
  assert.equal(resolved.response.status, 200);
  const resolution = resolved.body as { ok: true; authorization: StepUpAuthorization };
  assert.equal(resolution.ok, true);

  const binding = {
    authorization: resolution.authorization,
    subjectId: evaluation.decision.subjectId,
    action: evaluation.decision.action,
    actionSensitivity: evaluation.decision.actionSensitivity,
    resourceId: evaluation.decision.resourceId,
    contextHash: evaluation.decision.contextHash,
    policyId: evaluation.decision.policyId,
    policyVersion: evaluation.decision.policyVersion,
    credentialId: evaluation.decision.credentialId,
  };
  const consumed = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: binding,
  });
  assert.deepEqual(consumed.body, { authorized: true });
  const replay = await requestJson(app, "/step-up/authorizations/consume", {
    method: "POST",
    body: binding,
  });
  assert.deepEqual(replay.body, { authorized: false });
});

test("step-up rejection is an authority outcome and cannot produce an authorization", async () => {
  const { app, setNow } = harness();
  const subjectCredential = await issueCredential(app, { capabilities: ["records:export"] });
  const evaluated = await evaluate(app, subjectCredential, { effect: "STEP_UP", action: "records:export" });
  const evaluation = evaluated.body as { logId: string };
  const created = await requestJson(app, "/step-up/requests", {
    method: "POST",
    body: { decisionLogId: evaluation.logId, expiresAt: RECEIPT_EXPIRY },
  });
  const request = (created.body as { request: { id: string } }).request;
  const approverCredential = await issueCredential(app, {
    principalId: "principal:reviewer",
    capabilities: ["approval:records-export"],
  });
  setNow("2026-06-01T00:11:00.000Z");
  const rejected = await requestJson(app, `/step-up/requests/${encodeURIComponent(request.id)}/resolve`, {
    method: "POST",
    body: {
      resolution: "REJECT",
      approver: { id: approverCredential.principalId, affiliations: approverCredential.affiliations },
      approverCredential,
    },
  });
  assert.equal(rejected.response.status, 200);
  assert.deepEqual(rejected.body, { ok: false, reasonCode: "STEP_UP_REJECTED" });
});

test("expired and revoked credentials fail closed through evaluation", async () => {
  const expiredHarness = harness();
  const expired = await issueCredential(expiredHarness.app, {
    expiresAt: "2026-06-01T00:10:01.000Z",
  });
  expiredHarness.setNow("2026-06-01T00:10:01.000Z");
  const expiredDecision = await evaluate(expiredHarness.app, expired, { issueReceipt: false });
  assert.equal((expiredDecision.body as { decision: AccessDecision }).decision.reasonCode, "CREDENTIAL_EXPIRED");

  const revokedHarness = harness();
  const revoked = await issueCredential(revokedHarness.app);
  const revocation = await requestJson(
    revokedHarness.app,
    `/credentials/${encodeURIComponent(revoked.id)}/revoke`,
    { method: "POST", body: { reason: "reference-test" } },
  );
  assert.deepEqual(revocation.body, { revoked: true });
  const revokedDecision = await evaluate(revokedHarness.app, revoked, { issueReceipt: false });
  assert.equal((revokedDecision.body as { decision: AccessDecision }).decision.reasonCode, "CREDENTIAL_REVOKED");
});

test("decision/receipt history is read-only, reason-coded, reference-labeled, and defensive", async () => {
  const { app } = harness();
  const credential = await issueCredential(app);
  await evaluate(app, credential);
  const first = await requestJson(app, "/decision-log");
  const firstBody = first.body as {
    referenceOnly: boolean;
    entries: {
      decision: AccessDecision;
      receipt?: { payload: { reasonCode: string }; signatureHash: string; signature?: string };
    }[];
  };
  assert.equal(firstBody.referenceOnly, true);
  assert.equal(firstBody.entries.length, 1);
  assert.equal(firstBody.entries[0]?.decision.reasonCode, "POLICY_ALLOW");
  assert.equal(firstBody.entries[0]?.receipt?.payload.reasonCode, "POLICY_ALLOW");
  assert.match(firstBody.entries[0]?.receipt?.signatureHash ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.equal(firstBody.entries[0]?.receipt?.signature, undefined);
  (firstBody.entries[0] as { decision: { reasonCode: string } }).decision.reasonCode = "POLICY_DENY";
  if (firstBody.entries[0]?.receipt !== undefined) firstBody.entries[0].receipt.payload.reasonCode = "POLICY_DENY";
  const second = await requestJson(app, "/decision-log");
  assert.equal(
    (second.body as { entries: { decision: AccessDecision }[] }).entries[0]?.decision.reasonCode,
    "POLICY_ALLOW",
  );
  assert.equal(
    (second.body as { entries: { receipt?: { payload: { reasonCode: string } } }[] }).entries[0]?.receipt?.payload.reasonCode,
    "POLICY_ALLOW",
  );
});

test("unknown fields and malformed JSON are rejected at the transport boundary", async () => {
  const { app } = harness();
  const unknown = await requestJson(app, "/credentials", {
    method: "POST",
    body: {
      principal: { id: "principal:alice", affiliations: [], elevated: true },
      capabilities: [],
      expiresAt: EXPIRY,
    },
  });
  assert.equal(unknown.response.status, 400);
  assert.equal((unknown.body as { error: { code: string } }).error.code, "INVALID_REQUEST");

  const malformed = await requestJson(app, "/evaluations", {
    method: "POST",
    rawBody: "{not-json",
  });
  assert.equal(malformed.response.status, 400);
  assert.equal((malformed.body as { error: { code: string } }).error.code, "INVALID_REQUEST");

  const credential = await issueCredential(app);
  const unsupported = await requestJson(app, "/evaluations", {
    method: "POST",
    body: {
      principal: { id: credential.principalId, affiliations: credential.affiliations },
      credential,
      action: "records:read",
      resourceId: "record:1",
      actionContext: {},
      policy: policy("ALLOW"),
      issueReceipt: false,
      receiptExpiresAt: RECEIPT_EXPIRY,
      unsupported: true,
    },
  });
  assert.equal(unsupported.response.status, 400);
});

test("transport accepts exact JSON media types, rejects lookalikes, and disables caching", async () => {
  for (const contentType of [
    "application/jsonp",
    "foo/application/json",
    "text/plain; application/json=1",
    "text/plain",
  ]) {
    const { app } = harness();
    const result = await requestJson(app, "/credentials", {
      method: "POST",
      contentType,
      body: {
        principal: { id: "principal:alice", affiliations: [] },
        capabilities: [],
        expiresAt: EXPIRY,
      },
    });
    assert.equal(result.response.status, 415);
    assert.equal((result.body as { error: { code: string } }).error.code, "UNSUPPORTED_MEDIA_TYPE");
    assert.equal(result.response.headers.get("cache-control"), "no-store");
  }

  const { app } = harness();
  const accepted = await requestJson(app, "/credentials", {
    method: "POST",
    contentType: "application/problem+json; charset=utf-8",
    body: {
      principal: { id: "principal:alice", affiliations: [] },
      capabilities: [],
      expiresAt: EXPIRY,
    },
  });
  assert.equal(accepted.response.status, 201);
  assert.equal(accepted.response.headers.get("cache-control"), "no-store");
});

test("step-up creation requires a retained STEP_UP evaluator result and rejects decision injection", async () => {
  const { app } = harness();
  const credential = await issueCredential(app);
  const allowed = await evaluate(app, credential, { effect: "ALLOW" });
  const allowedLogId = (allowed.body as { logId: string }).logId;

  const wrongOutcome = await requestJson(app, "/step-up/requests", {
    method: "POST",
    body: { decisionLogId: allowedLogId, expiresAt: RECEIPT_EXPIRY },
  });
  assert.equal(wrongOutcome.response.status, 400);

  const injected = await requestJson(app, "/step-up/requests", {
    method: "POST",
    body: {
      decisionLogId: "decision-log:missing",
      decision: { outcome: "STEP_UP", reasonCode: "HUMAN_APPROVAL_REQUIRED" },
      expiresAt: RECEIPT_EXPIRY,
    },
  });
  assert.equal(injected.response.status, 400);
  assert.equal((injected.body as { error: { code: string } }).error.code, "INVALID_REQUEST");
});

test("transport rejects prototype-control fields while canonical context preserves them as data", async () => {
  const { app } = harness();
  const topLevelPrototypeField = await requestJson(app, "/credentials", {
    method: "POST",
    rawBody: '{"__proto__":{"admin":true},"principal":{"id":"principal:alice","affiliations":[]},"capabilities":[],"expiresAt":"2026-06-01T01:00:00.000Z"}',
  });
  assert.equal(topLevelPrototypeField.response.status, 400);

  const credential = await issueCredential(app);
  const base = {
    principal: { id: credential.principalId, affiliations: credential.affiliations },
    credential,
    action: "records:read",
    resourceId: "record:prototype-context",
    policy: policy("ALLOW"),
    issueReceipt: false,
  };
  const empty = await requestJson(app, "/evaluations", {
    method: "POST",
    body: { ...base, actionContext: {} },
  });
  const proto = await requestJson(app, "/evaluations", {
    method: "POST",
    rawBody: JSON.stringify({ ...base, actionContext: JSON.parse('{"__proto__":{"admin":true}}') }),
  });
  assert.notEqual(
    (empty.body as { decision: AccessDecision }).decision.contextHash,
    (proto.body as { decision: AccessDecision }).decision.contextHash,
  );
});
