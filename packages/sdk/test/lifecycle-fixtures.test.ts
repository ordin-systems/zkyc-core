import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createReferenceApp, type ReferenceIdKind } from "@ordin/zkyc-core-api-reference";
import {
  ZkycApiError,
  ZkycReferenceClient,
  type AccessDecision,
  type BoundAccessDecision,
  type CapabilityDelegation,
  type Credential,
  type ReceiptExpectedBinding,
  type SignedReceipt,
  type StepUpAuthorization,
} from "../src/index.js";

const OPERATIONS = [
  "issueCredential",
  "issueDelegation",
  "revokeCredential",
  "revokeDelegation",
  "evaluate",
  "createStepUpRequest",
  "resolveStepUp",
  "consumeAuthorization",
  "consumeReceipt",
  "getOnboardingView",
] as const;
const ID_KINDS: readonly ReferenceIdKind[] = [
  "credential",
  "delegation",
  "decision-log",
  "step-up-request",
  "receipt-nonce",
];
const REQUIRED_LANES = [
  "direct-allow-receipt-replay",
  "explicit-deny",
  "direct-step-up-approval",
  "step-up-rejection",
  "expired-credential",
  "revoked-credential",
  "delegated-allow-receipt",
  "active-delegation",
  "expired-delegation",
  "revoked-delegation",
  "credential-action-scope-mismatch",
  "credential-resource-scope-mismatch",
  "delegation-action-scope-mismatch",
  "delegation-resource-scope-mismatch",
] as const;

type Operation = (typeof OPERATIONS)[number];
type JsonRecord = Record<string, unknown>;
interface TranscriptStep {
  readonly op: Operation;
  readonly at: string;
  readonly as?: string;
  readonly input: JsonRecord;
  readonly expect: JsonRecord & { readonly status: number };
}
interface LifecycleTranscript {
  readonly name: string;
  readonly fixed: {
    readonly initialClock: string;
    readonly referenceKeyBytes: readonly number[];
    readonly idsByKind: Readonly<Record<ReferenceIdKind, readonly string[]>>;
  };
  readonly steps: readonly TranscriptStep[];
}
interface LifecycleFixture {
  readonly version: 1;
  readonly transcripts: readonly LifecycleTranscript[];
}

function record(value: unknown, label: string): JsonRecord {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must be an object`);
  assert.equal(Array.isArray(value), false, `${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  assert.ok(prototype === Object.prototype || prototype === null, `${label} must be plain`);
  return value as JsonRecord;
}

function exact(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): JsonRecord {
  const result = record(value, label);
  const allowed = new Set([...required, ...optional]);
  assert.deepEqual(
    Object.keys(result).filter((key) => !allowed.has(key)),
    [],
    `${label} has unknown fields`,
  );
  for (const key of required) assert.ok(Object.hasOwn(result, key), `${label}.${key} is required`);
  return result;
}

function text(value: unknown, label: string): string {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok((value as string).length > 0, `${label} must not be empty`);
  return value as string;
}

function canonicalTimestamp(value: unknown, label: string): string {
  const result = text(value, label);
  assert.equal(new Date(result).toISOString(), result, `${label} must be a canonical timestamp`);
  return result;
}

function stringList(value: unknown, label: string): readonly string[] {
  assert.ok(Array.isArray(value), `${label} must be an array`);
  value.forEach((entry, index) => text(entry, `${label}[${index}]`));
  return value as readonly string[];
}

function symbolicReference(value: unknown, label: string): void {
  assert.match(text(value, label), /^\$[a-z][a-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9]*)*$/);
}

function validateAffiliations(value: unknown, label: string): void {
  assert.ok(Array.isArray(value), `${label} must be an array`);
  value.forEach((item, index) => {
    const affiliation = exact(item, ["organizationId", "role"], [], `${label}[${index}]`);
    text(affiliation.organizationId, `${label}[${index}].organizationId`);
    text(affiliation.role, `${label}[${index}].role`);
  });
}

function validatePrincipal(value: unknown, label: string): void {
  const principal = exact(value, ["id", "type", "affiliations"], [], label);
  text(principal.id, `${label}.id`);
  assert.ok(["HUMAN", "ORGANIZATION", "AGENT"].includes(text(principal.type, `${label}.type`)));
  validateAffiliations(principal.affiliations, `${label}.affiliations`);
}

function validatePolicy(value: unknown, label: string): void {
  const policy = exact(value, ["id", "rules"], [], label);
  text(policy.id, `${label}.id`);
  assert.ok(Array.isArray(policy.rules) && policy.rules.length > 0, `${label}.rules must be non-empty`);
  policy.rules.forEach((item, index) => {
    const rule = exact(
      item,
      ["action", "actionSensitivity", "requiredCapabilities", "requiredAffiliations", "effect"],
      ["approverCapability"],
      `${label}.rules[${index}]`,
    );
    text(rule.action, `${label}.rules[${index}].action`);
    assert.ok(["ROUTINE", "SENSITIVE", "CRITICAL"].includes(text(rule.actionSensitivity, "actionSensitivity")));
    stringList(rule.requiredCapabilities, `${label}.rules[${index}].requiredCapabilities`);
    validateAffiliations(rule.requiredAffiliations, `${label}.rules[${index}].requiredAffiliations`);
    assert.ok(["ALLOW", "DENY", "STEP_UP"].includes(text(rule.effect, "effect")));
    if (rule.approverCapability !== undefined) text(rule.approverCapability, "approverCapability");
  });
}

function validateCredentialInput(value: unknown, label: string): void {
  const input = exact(
    value,
    ["principal", "capabilities", "allowedActions", "allowedResourceIds", "expiresAt"],
    ["unverifiedMetadata"],
    label,
  );
  validatePrincipal(input.principal, `${label}.principal`);
  stringList(input.capabilities, `${label}.capabilities`);
  stringList(input.allowedActions, `${label}.allowedActions`);
  stringList(input.allowedResourceIds, `${label}.allowedResourceIds`);
  canonicalTimestamp(input.expiresAt, `${label}.expiresAt`);
  if (input.unverifiedMetadata !== undefined) {
    const metadata = exact(
      input.unverifiedMetadata,
      [],
      ["zkPassProofId", "contextualProofIds"],
      `${label}.unverifiedMetadata`,
    );
    if (metadata.zkPassProofId !== undefined) text(metadata.zkPassProofId, "zkPassProofId");
    if (metadata.contextualProofIds !== undefined) stringList(metadata.contextualProofIds, "contextualProofIds");
  }
}

function validateStepInput(op: Operation, value: unknown, label: string): void {
  if (op === "issueCredential") return validateCredentialInput(value, label);
  if (op === "issueDelegation") {
    const input = exact(
      value,
      ["grantorCredential", "delegateCredential", "policy", "capabilities", "allowedActions", "allowedResourceIds", "expiresAt"],
      [],
      label,
    );
    symbolicReference(input.grantorCredential, `${label}.grantorCredential`);
    symbolicReference(input.delegateCredential, `${label}.delegateCredential`);
    validatePolicy(input.policy, `${label}.policy`);
    stringList(input.capabilities, `${label}.capabilities`);
    stringList(input.allowedActions, `${label}.allowedActions`);
    stringList(input.allowedResourceIds, `${label}.allowedResourceIds`);
    canonicalTimestamp(input.expiresAt, `${label}.expiresAt`);
    return;
  }
  if (op === "revokeCredential" || op === "revokeDelegation") {
    const artifact = op === "revokeCredential" ? "credential" : "delegation";
    const input = exact(value, [artifact, "reason"], [], label);
    symbolicReference(input[artifact], `${label}.${artifact}`);
    text(input.reason, `${label}.reason`);
    return;
  }
  if (op === "evaluate") {
    const initial = record(value, label);
    const mode = text(initial.authorityMode, `${label}.authorityMode`);
    const common = ["authorityMode", "action", "resourceId", "actionContext", "policy", "issueReceipt"];
    const refs = mode === "DIRECT"
      ? ["credential"]
      : ["delegateIdentityCredential", "grantorCredential", "delegation"];
    assert.ok(mode === "DIRECT" || mode === "DELEGATED", `${label}.authorityMode is invalid`);
    const input = exact(value, [...common, ...refs], ["receiptExpiresAt"], label);
    refs.forEach((key) => symbolicReference(input[key], `${label}.${key}`));
    text(input.action, `${label}.action`);
    text(input.resourceId, `${label}.resourceId`);
    record(input.actionContext, `${label}.actionContext`);
    validatePolicy(input.policy, `${label}.policy`);
    assert.equal(typeof input.issueReceipt, "boolean", `${label}.issueReceipt must be boolean`);
    if (input.receiptExpiresAt !== undefined) canonicalTimestamp(input.receiptExpiresAt, `${label}.receiptExpiresAt`);
    return;
  }
  if (op === "createStepUpRequest") {
    const input = exact(value, ["evaluation", "expiresAt"], [], label);
    symbolicReference(input.evaluation, `${label}.evaluation`);
    canonicalTimestamp(input.expiresAt, `${label}.expiresAt`);
    return;
  }
  if (op === "resolveStepUp") {
    const input = exact(value, ["request", "resolution", "approverCredential"], [], label);
    symbolicReference(input.request, `${label}.request`);
    symbolicReference(input.approverCredential, `${label}.approverCredential`);
    assert.ok(["APPROVE", "REJECT"].includes(text(input.resolution, `${label}.resolution`)));
    return;
  }
  if (op === "consumeAuthorization") {
    const input = exact(value, ["authorization"], [], label);
    symbolicReference(input.authorization, `${label}.authorization`);
    return;
  }
  if (op === "consumeReceipt") {
    const input = exact(value, ["evaluation"], [], label);
    symbolicReference(input.evaluation, `${label}.evaluation`);
    return;
  }
  const input = record(value, label);
  const keys = Object.keys(input);
  assert.ok(
    keys.length === 1 && (keys[0] === "evaluation" || keys[0] === "decisionLogId"),
    `${label} must select exactly one retained decision`,
  );
  if (input.evaluation !== undefined) symbolicReference(input.evaluation, `${label}.evaluation`);
  else text(input.decisionLogId, `${label}.decisionLogId`);
}

function validateExpectation(op: Operation, value: unknown, label: string): void {
  const initial = record(value, label);
  assert.equal(Number.isInteger(initial.status), true, `${label}.status must be an integer`);
  let required: readonly string[];
  if (op === "issueCredential" || op === "issueDelegation") required = ["status"];
  else if (op === "revokeCredential" || op === "revokeDelegation") required = ["status", "revoked"];
  else if (op === "evaluate") required = ["status", "outcome", "reasonCode"];
  else if (op === "createStepUpRequest") required = ["status", "approvalStatus", "decisionLogId"];
  else if (op === "resolveStepUp") {
    required = initial.approvalStatus === "REJECTED"
      ? ["status", "reasonCode", "approvalStatus"]
      : ["status", "approvalStatus"];
  } else if (op === "consumeAuthorization") required = ["status", "authorized"];
  else if (op === "consumeReceipt") required = ["status", "reasonCode", "valid"];
  else {
    required = initial.status === 200
      ? ["status", "reasonCode", "receipt", "verificationStatus", "approvalStatus"]
      : ["status", "reasonCode"];
  }
  const expectation = exact(value, required, [], label);
  for (const key of ["revoked", "authorized", "valid"]) {
    if (expectation[key] !== undefined) assert.equal(typeof expectation[key], "boolean", `${label}.${key} must be boolean`);
  }
  for (const key of [
    "outcome",
    "reasonCode",
    "verificationStatus",
    "approvalStatus",
    "decisionLogId",
  ]) {
    if (expectation[key] !== undefined) text(expectation[key], `${label}.${key}`);
  }
  if (op === "consumeReceipt") {
    assert.equal(
      expectation.valid,
      expectation.reasonCode === "RECEIPT_VALID",
      `${label} receipt validity and reasonCode contradict`,
    );
  }
  if (expectation.receipt !== undefined) {
    const receipt = exact(expectation.receipt, ["consumptionStatus", "lastAttempt"], [], `${label}.receipt`);
    const consumptionStatus = text(receipt.consumptionStatus, `${label}.receipt.consumptionStatus`);
    assert.ok(
      ["NOT_ISSUED", "UNCONSUMED", "CONSUMED"].includes(consumptionStatus),
      `${label}.receipt.consumptionStatus is invalid`,
    );
    const attempt = record(receipt.lastAttempt, `${label}.receipt.lastAttempt`);
    const outcome = text(attempt.outcome, `${label}.receipt.lastAttempt.outcome`);
    if (outcome === "NONE") {
      exact(attempt, ["outcome"], [], `${label}.receipt.lastAttempt`);
    } else {
      assert.ok(outcome === "ACCEPTED" || outcome === "REJECTED", `${label}.receipt.lastAttempt.outcome is invalid`);
      exact(attempt, ["outcome", "reasonCode"], [], `${label}.receipt.lastAttempt`);
      const reasonCode = text(attempt.reasonCode, `${label}.receipt.lastAttempt.reasonCode`);
      if (outcome === "ACCEPTED") {
        assert.equal(reasonCode, "RECEIPT_VALID", `${label}.receipt accepted reason is invalid`);
      } else {
        assert.ok(
          [
            "RECEIPT_SIGNATURE_INVALID",
            "RECEIPT_NOT_YET_VALID",
            "RECEIPT_EXPIRED",
            "RECEIPT_BINDING_MISMATCH",
            "RECEIPT_NOT_AUTHORIZING",
            "RECEIPT_CREDENTIAL_INVALID",
            "RECEIPT_AUTHORITY_INVALID",
            "RECEIPT_REPLAYED",
          ].includes(reasonCode),
          `${label}.receipt rejected reason is invalid`,
        );
      }
    }
    assert.ok(
      (consumptionStatus === "NOT_ISSUED" && outcome === "NONE") ||
        (consumptionStatus === "UNCONSUMED" && outcome !== "ACCEPTED") ||
        (consumptionStatus === "CONSUMED" && outcome !== "NONE"),
      `${label}.receipt status and last attempt contradict`,
    );
  }
}

function validateFixture(value: unknown): LifecycleFixture {
  const root = exact(value, ["version", "transcripts"], [], "fixture");
  assert.equal(root.version, 1, "fixture.version must equal 1");
  assert.ok(Array.isArray(root.transcripts) && root.transcripts.length > 0, "fixture.transcripts must be non-empty");
  const names = new Set<string>();
  root.transcripts.forEach((item, transcriptIndex) => {
    const transcript = exact(item, ["name", "fixed", "steps"], [], `transcripts[${transcriptIndex}]`);
    const name = text(transcript.name, `transcripts[${transcriptIndex}].name`);
    assert.equal(names.has(name), false, `duplicate transcript ${name}`);
    names.add(name);
    const fixed = exact(transcript.fixed, ["initialClock", "referenceKeyBytes", "idsByKind"], [], `${name}.fixed`);
    canonicalTimestamp(fixed.initialClock, `${name}.fixed.initialClock`);
    assert.ok(Array.isArray(fixed.referenceKeyBytes) && fixed.referenceKeyBytes.length === 32, `${name} key must have 32 bytes`);
    fixed.referenceKeyBytes.forEach((byte, index) => {
      assert.ok(Number.isInteger(byte) && (byte as number) >= 0 && (byte as number) <= 255, `${name} key byte ${index} is invalid`);
    });
    const ids = exact(fixed.idsByKind, ID_KINDS, [], `${name}.fixed.idsByKind`);
    ID_KINDS.forEach((kind) => stringList(ids[kind], `${name}.fixed.idsByKind.${kind}`));
    assert.ok(Array.isArray(transcript.steps) && transcript.steps.length > 0, `${name}.steps must be non-empty`);
    const handles = new Set<string>();
    transcript.steps.forEach((itemStep, stepIndex) => {
      const stepValue = exact(itemStep, ["op", "at", "input", "expect"], ["as"], `${name}.steps[${stepIndex}]`);
      const op = text(stepValue.op, `${name}.steps[${stepIndex}].op`);
      assert.ok(OPERATIONS.includes(op as Operation), `${name} has unsupported operation ${op}`);
      canonicalTimestamp(stepValue.at, `${name}.steps[${stepIndex}].at`);
      if (stepValue.as !== undefined) {
        const handle = text(stepValue.as, `${name}.steps[${stepIndex}].as`);
        assert.match(handle, /^[a-z][a-z0-9-]*$/);
        assert.equal(handles.has(handle), false, `${name} duplicates handle ${handle}`);
        handles.add(handle);
      }
      validateStepInput(op as Operation, stepValue.input, `${name}.steps[${stepIndex}].input`);
      validateExpectation(op as Operation, stepValue.expect, `${name}.steps[${stepIndex}].expect`);
    });
  });
  return value as LifecycleFixture;
}

function principalFor(credential: Credential) {
  return {
    id: credential.principalId,
    type: credential.principalType,
    affiliations: credential.affiliations,
  };
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
    assert.ok(decision.credentialId);
    return { ...common, authorityMode: "DIRECT", credentialId: decision.credentialId };
  }
  assert.ok(decision.grantorId);
  assert.ok(decision.grantorType);
  assert.ok(decision.grantorCredentialId);
  assert.ok(decision.delegationId);
  assert.ok(decision.delegationBindingHash);
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

function authorizationBinding(authorization: StepUpAuthorization): JsonRecord {
  const { version: _version, id: _id, issuedAt: _issuedAt, expiresAt: _expiresAt, ...binding } = authorization;
  return { authorization, ...binding } as JsonRecord;
}

function resolveReference(value: unknown, handles: ReadonlyMap<string, unknown>): unknown {
  const reference = text(value, "symbolic reference");
  assert.match(reference, /^\$/);
  const [handle, ...fields] = reference.slice(1).split(".");
  assert.ok(handle !== undefined && handles.has(handle), `unknown symbolic handle ${reference}`);
  let result = handles.get(handle);
  for (const field of fields) {
    assert.ok(typeof result === "object" && result !== null && Object.hasOwn(result, field), `unresolved symbolic reference ${reference}`);
    result = (result as JsonRecord)[field];
  }
  return result;
}

function assertExpected(step: TranscriptStep, actual: { readonly status: number; readonly body: JsonRecord }): void {
  assert.equal(actual.status, step.expect.status, `${step.op} HTTP status`);
  const body = actual.body;
  const observed: JsonRecord = {
    outcome: (body.decision as JsonRecord | undefined)?.outcome,
    reasonCode: (body.decision as JsonRecord | undefined)?.reasonCode ?? body.reasonCode ??
      (body.error as JsonRecord | undefined)?.code ??
      ((body.eligibleActions as JsonRecord[] | undefined)?.[0]?.reasonCode),
    receipt: body.receipt,
    verificationStatus: body.verificationStatus,
    approvalStatus: (body.request as JsonRecord | undefined)?.status ??
      (body.requiredApproval as JsonRecord | undefined)?.status ??
      (body.ok === true ? "APPROVED" : body.ok === false ? "REJECTED" : undefined),
    decisionLogId: body.decisionLogId,
    authorized: body.authorized,
    valid: body.valid,
    revoked: body.revoked,
  };
  for (const [key, expected] of Object.entries(step.expect)) {
    if (key !== "status") assert.deepEqual(observed[key], expected, `${step.op} ${key}`);
  }
}

async function executeTranscript(transcript: LifecycleTranscript): Promise<readonly Operation[]> {
  let now = transcript.fixed.initialClock;
  let observedStatus = 0;
  const queues = new Map(
    ID_KINDS.map((kind) => [kind, [...(transcript.fixed.idsByKind[kind] ?? [])]]),
  );
  const trustedPolicies = [...new Map(
    transcript.steps.flatMap((step) =>
      step.input.policy === undefined
        ? []
        : [[JSON.stringify(step.input.policy), step.input.policy] as const]
    ),
  ).values()];
  const app = createReferenceApp({
    clock: () => now,
    idFactory: (kind: ReferenceIdKind) => {
      const next = queues.get(kind)?.shift();
      assert.ok(next, `${transcript.name} exhausted ${kind} IDs`);
      return next;
    },
    receiptHmacKey: Uint8Array.from(transcript.fixed.referenceKeyBytes),
    trustedPolicies: trustedPolicies as never[],
    issuerId: `issuer:fixture:${transcript.name}`,
  });
  const client = new ZkycReferenceClient({
    baseUrl: "https://fixture.reference/",
    fetch: async (input, init) => {
      const response = await app.request(String(input), init);
      observedStatus = response.status;
      return response;
    },
  });
  const sdkCall = async (
    action: () => Promise<unknown>,
  ): Promise<{ readonly status: number; readonly body: JsonRecord }> => {
    observedStatus = 0;
    try {
      const body = await action();
      return { status: observedStatus, body: record(body, "SDK response") };
    } catch (error) {
      if (error instanceof ZkycApiError) {
        return {
          status: error.status,
          body: { error: { code: error.code, message: error.message } },
        };
      }
      throw error;
    }
  };
  const handles = new Map<string, unknown>();
  const executed: Operation[] = [];
  for (const step of transcript.steps) {
    now = step.at;
    const input = step.input;
    let actual: { readonly status: number; readonly body: JsonRecord };
    let retained: unknown;
    switch (step.op) {
      case "issueCredential": {
        actual = await sdkCall(() => client.issueCredential(
          input as unknown as Parameters<ZkycReferenceClient["issueCredential"]>[0],
        ));
        retained = actual.body.credential;
        break;
      }
      case "issueDelegation": {
        const grantorCredential = resolveReference(input.grantorCredential, handles) as Credential;
        const delegateCredential = resolveReference(input.delegateCredential, handles) as Credential;
        actual = await sdkCall(() => client.issueDelegation({
          grantor: principalFor(grantorCredential),
          grantorCredential,
          delegate: principalFor(delegateCredential),
          policy: input.policy as Parameters<ZkycReferenceClient["issueDelegation"]>[0]["policy"],
          capabilities: input.capabilities as readonly string[],
          allowedActions: input.allowedActions as readonly string[],
          allowedResourceIds: input.allowedResourceIds as readonly string[],
          expiresAt: input.expiresAt as string,
        }));
        retained = actual.body.delegation;
        break;
      }
      case "revokeCredential": {
        const credential = resolveReference(input.credential, handles) as Credential;
        actual = await sdkCall(() => client.revokeCredential(credential.id, {
          reason: input.reason as string,
        }));
        break;
      }
      case "revokeDelegation": {
        const delegation = resolveReference(input.delegation, handles) as CapabilityDelegation;
        actual = await sdkCall(() => client.revokeDelegation(delegation.id, {
          reason: input.reason as string,
        }));
        break;
      }
      case "evaluate": {
        const common = {
          action: input.action as string,
          resourceId: input.resourceId as string,
          actionContext: input.actionContext as Readonly<Record<string, unknown>>,
          policy: input.policy as Parameters<ZkycReferenceClient["evaluate"]>[0]["policy"],
          issueReceipt: input.issueReceipt as boolean,
          ...(input.receiptExpiresAt === undefined
            ? {}
            : { receiptExpiresAt: input.receiptExpiresAt as string }),
        };
        if (input.authorityMode === "DIRECT") {
          const credential = resolveReference(input.credential, handles) as Credential;
          actual = await sdkCall(() => client.evaluate({
            ...common,
            authorityMode: "DIRECT",
            principal: principalFor(credential),
            credential,
          }));
        } else {
          const delegateIdentityCredential = resolveReference(
            input.delegateIdentityCredential,
            handles,
          ) as Credential;
          const grantorCredential = resolveReference(input.grantorCredential, handles) as Credential;
          const delegation = resolveReference(input.delegation, handles) as CapabilityDelegation;
          actual = await sdkCall(() => client.evaluate({
            ...common,
            authorityMode: "DELEGATED",
            principal: principalFor(delegateIdentityCredential),
            delegateIdentityCredential,
            grantorCredential,
            delegation,
          }));
        }
        retained = actual.body;
        break;
      }
      case "createStepUpRequest": {
        const evaluation = resolveReference(input.evaluation, handles) as JsonRecord;
        actual = await sdkCall(() => client.createStepUpRequest({
          decisionLogId: evaluation.logId as string,
          expiresAt: input.expiresAt as string,
        }));
        retained = actual.body.request;
        break;
      }
      case "resolveStepUp": {
        const request = resolveReference(input.request, handles) as { readonly id: string };
        const approverCredential = resolveReference(input.approverCredential, handles) as Credential;
        actual = await sdkCall(() => client.resolveStepUpRequest(request.id, {
          resolution: input.resolution as "APPROVE" | "REJECT",
          approver: principalFor(approverCredential),
          approverCredential,
        }));
        retained = actual.body.authorization;
        break;
      }
      case "consumeAuthorization": {
        const authorization = resolveReference(input.authorization, handles) as StepUpAuthorization;
        actual = await sdkCall(() => client.consumeStepUpAuthorization(
          authorizationBinding(authorization) as unknown as Parameters<
            ZkycReferenceClient["consumeStepUpAuthorization"]
          >[0],
        ));
        break;
      }
      case "consumeReceipt": {
        const evaluation = resolveReference(input.evaluation, handles) as JsonRecord;
        actual = await sdkCall(() => client.consumeReceipt({
          receipt: evaluation.receipt as SignedReceipt,
          expected: receiptExpected(evaluation.decision as AccessDecision),
        }));
        break;
      }
      case "getOnboardingView": {
        const decisionLogId = input.evaluation === undefined
          ? input.decisionLogId as string
          : (resolveReference(input.evaluation, handles) as JsonRecord).logId as string;
        actual = await sdkCall(() => client.getOnboardingView(decisionLogId));
        break;
      }
    }
    assertExpected(step, actual);
    if (step.as !== undefined) {
      assert.notEqual(retained, undefined, `${step.op} did not retain ${step.as}`);
      handles.set(step.as, retained);
    }
    executed.push(step.op);
  }
  for (const kind of ID_KINDS) {
    assert.deepEqual(queues.get(kind), [], `${transcript.name} left unused ${kind} IDs`);
  }
  return executed;
}

async function loadFixture(): Promise<LifecycleFixture> {
  const url = new URL("../../../../fixtures/full-stack-reference-cases.json", import.meta.url);
  return validateFixture(JSON.parse(await readFile(url, "utf8")));
}

test("versioned lifecycle fixture schema rejects unknown and missing fields before SDK execution", async () => {
  const fixture = await loadFixture();
  const unknown = structuredClone(fixture) as unknown as JsonRecord;
  (unknown.transcripts as JsonRecord[])[0]!.unexpected = true;
  assert.throws(() => validateFixture(unknown), /unknown fields/);
  const missing = structuredClone(fixture) as unknown as JsonRecord;
  delete ((missing.transcripts as JsonRecord[])[0]!.steps as JsonRecord[])[0]!.expect;
  assert.throws(() => validateFixture(missing), /expect is required/);
  const unknownInput = structuredClone(fixture) as unknown as JsonRecord;
  ((((unknownInput.transcripts as JsonRecord[])[0]!.steps as JsonRecord[])[0]!.input) as JsonRecord).unexpected = true;
  assert.throws(() => validateFixture(unknownInput), /unknown fields/);
  const unknownExpectation = structuredClone(fixture) as unknown as JsonRecord;
  ((((unknownExpectation.transcripts as JsonRecord[])[0]!.steps as JsonRecord[])[0]!.expect) as JsonRecord).unexpected = true;
  assert.throws(() => validateFixture(unknownExpectation), /unknown fields/);
});

test("SDK runner executes every versioned authority lifecycle transcript step", async () => {
  const fixture = await loadFixture();
  const laneNames = new Set(fixture.transcripts.map((transcript) => transcript.name));
  REQUIRED_LANES.forEach((lane) => assert.ok(laneNames.has(lane), `missing lifecycle lane ${lane}`));
  const executed = new Set<Operation>();
  let executedCount = 0;
  for (const transcript of fixture.transcripts) {
    const operations = await executeTranscript(transcript);
    operations.forEach((operation) => executed.add(operation));
    executedCount += operations.length;
  }
  assert.equal(executedCount, fixture.transcripts.reduce((count, transcript) => count + transcript.steps.length, 0));
  assert.deepEqual([...executed].sort(), [...OPERATIONS].sort());
});
