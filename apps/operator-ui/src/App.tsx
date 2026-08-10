import { useCallback, useMemo, useState } from "react";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type AccessDecision,
  type BoundAccessDecision,
  type CapabilityDelegation,
  type Credential,
  type DecisionLogEntry,
  type ReceiptExpectedBinding,
  type SignedReceipt,
  type StepUpAuthorization,
  type StepUpRequest,
} from "@ordin/zkyc-sdk-reference";
import { scenarios } from "./scenarios.js";

const defaultClient = new ZkycReferenceClient({
  baseUrl: import.meta.env.VITE_ZKYC_API_URL ?? "/api/",
});

export type CockpitClient = Pick<
  ZkycReferenceClient,
  | "issueCredential"
  | "issueDelegation"
  | "evaluate"
  | "createStepUpRequest"
  | "resolveStepUpRequest"
  | "consumeStepUpAuthorization"
  | "consumeReceipt"
  | "getDecisionLog"
>;

export interface AppProps {
  readonly client?: CockpitClient;
}

interface PresentedAuthority {
  readonly actingCredential: Credential;
  readonly effectiveCapabilities: readonly string[];
  readonly effectiveActions: readonly string[];
  readonly effectiveResources: readonly string[];
  readonly delegation?: CapabilityDelegation;
}

function future(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function errorMessage(error: unknown): string {
  if (error instanceof ZkycApiError) return `API rejected the request: ${error.code}`;
  if (error instanceof ZkycTransportError) return `Transport unavailable: ${error.code}`;
  return "The reference flow failed closed.";
}

function isBoundDecision(decision: AccessDecision): decision is BoundAccessDecision {
  return decision.actingCredentialId !== undefined && decision.effectiveScopeHash !== undefined;
}

function receiptExpectedBinding(decision: AccessDecision): ReceiptExpectedBinding {
  if (!isBoundDecision(decision)) throw new Error("receipt decision is missing authority bindings");
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
    if (decision.credentialId === undefined) throw new Error("direct decision is missing credentialId");
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

export function App({ client = defaultClient }: AppProps = {}) {
  const [scenarioId, setScenarioId] = useState(scenarios[0]?.id ?? "");
  const [decision, setDecision] = useState<AccessDecision | null>(null);
  const [receipt, setReceipt] = useState<SignedReceipt | null>(null);
  const [stepUpRequest, setStepUpRequest] = useState<StepUpRequest | null>(null);
  const [authorization, setAuthorization] = useState<StepUpAuthorization | null>(null);
  const [presentedAuthority, setPresentedAuthority] = useState<PresentedAuthority | null>(null);
  const [resolutionReason, setResolutionReason] = useState<string | null>(null);
  const [consumption, setConsumption] = useState<string | null>(null);
  const [entries, setEntries] = useState<readonly DecisionLogEntry[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const scenario = useMemo(
    () => scenarios.find((candidate) => candidate.id === scenarioId) ?? scenarios[0],
    [scenarioId],
  );

  const refreshLog = useCallback(async () => {
    const log = await client.getDecisionLog();
    setEntries(log.entries);
  }, [client]);

  const refreshLogSafely = useCallback(async () => {
    setBusy("refresh");
    setError(null);
    try {
      await refreshLog();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }, [refreshLog]);

  async function evaluateScenario() {
    if (scenario === undefined) return;
    setBusy("evaluate");
    setError(null);
    setDecision(null);
    setReceipt(null);
    setStepUpRequest(null);
    setAuthorization(null);
    setPresentedAuthority(null);
    setResolutionReason(null);
    setConsumption(null);
    try {
      let evaluated: Awaited<ReturnType<CockpitClient["evaluate"]>>;
      if (scenario.authorityMode === "DIRECT") {
        const issued = await client.issueCredential({
          principal: scenario.principal,
          capabilities: scenario.capabilities,
          allowedActions: scenario.allowedActions,
          allowedResourceIds: scenario.allowedResourceIds,
          expiresAt: future(60),
        });
        evaluated = await client.evaluate({
          authorityMode: "DIRECT",
          principal: scenario.principal,
          credential: issued.credential,
          action: scenario.action,
          resourceId: scenario.resourceId,
          actionContext: scenario.actionContext,
          policy: scenario.policy,
          issueReceipt: true,
          receiptExpiresAt: future(15),
        });
        setPresentedAuthority({
          actingCredential: issued.credential,
          effectiveCapabilities: issued.credential.capabilities,
          effectiveActions: issued.credential.allowedActions,
          effectiveResources: issued.credential.allowedResourceIds,
        });
      } else {
        const grantor = {
          id: "organization:reference-grantor",
          type: "ORGANIZATION",
          affiliations: [],
        } as const;
        const { credential: grantorCredential } = await client.issueCredential({
          principal: grantor,
          capabilities: ["records:read", "records:write"],
          allowedActions: ["records:read", "records:write"],
          allowedResourceIds: [scenario.resourceId, "record:reference-reserve"],
          expiresAt: future(60),
        });
        const { credential: delegateIdentityCredential } = await client.issueCredential({
          principal: scenario.principal,
          capabilities: ["identity:present"],
          allowedActions: ["identity:present"],
          allowedResourceIds: [scenario.principal.id],
          expiresAt: future(60),
        });
        const { delegation } = await client.issueDelegation({
          grantor,
          grantorCredential,
          delegate: scenario.principal,
          policy: scenario.policy,
          capabilities: scenario.capabilities,
          allowedActions: scenario.allowedActions,
          allowedResourceIds: scenario.allowedResourceIds,
          expiresAt: future(30),
        });
        evaluated = await client.evaluate({
          authorityMode: "DELEGATED",
          principal: scenario.principal,
          delegateIdentityCredential,
          grantorCredential,
          delegation,
          action: scenario.action,
          resourceId: scenario.resourceId,
          actionContext: scenario.actionContext,
          policy: scenario.policy,
          issueReceipt: true,
          receiptExpiresAt: future(15),
        });
        setPresentedAuthority({
          actingCredential: delegateIdentityCredential,
          effectiveCapabilities: delegation.capabilities,
          effectiveActions: delegation.allowedActions,
          effectiveResources: delegation.allowedResourceIds,
          delegation,
        });
      }
      setDecision(evaluated.decision);
      setReceipt(evaluated.receipt ?? null);
      if (evaluated.decision.outcome === "STEP_UP") {
        const created = await client.createStepUpRequest({
          decisionLogId: evaluated.logId,
          expiresAt: future(15),
        });
        setStepUpRequest(created.request);
      }
      await refreshLog();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function resolveStepUp(resolution: "APPROVE" | "REJECT") {
    if (stepUpRequest === null) return;
    setBusy("resolve");
    setError(null);
    setResolutionReason(null);
    try {
      const approver = {
        id: "principal:reference-approver",
        type: "HUMAN",
        affiliations: [{ organizationId: "organization:reference", role: "reviewer" }],
      } as const;
      const issued = await client.issueCredential({
        principal: approver,
        capabilities: [stepUpRequest.requiredApproverCapability],
        allowedActions: ["step-up:resolve"],
        allowedResourceIds: [stepUpRequest.resourceId],
        expiresAt: future(60),
      });
      const resolved = await client.resolveStepUpRequest(stepUpRequest.id, {
        resolution,
        approver,
        approverCredential: issued.credential,
      });
      if (resolved.ok) {
        setAuthorization(resolved.authorization);
        setResolutionReason("STEP_UP_APPROVED");
      } else {
        setAuthorization(null);
        setResolutionReason(resolved.reasonCode);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function consumeAuthority() {
    if (decision === null) return;
    setBusy("consume");
    setError(null);
    try {
      if (receipt !== null) {
        const result = await client.consumeReceipt({
          receipt,
          expected: receiptExpectedBinding(decision),
        });
        setConsumption(result.reasonCode);
      } else if (authorization !== null) {
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
        const input = authorization.authorityMode === "DIRECT"
          ? {
              ...common,
              authorityMode: "DIRECT" as const,
              credentialId: authorization.credentialId ?? authorization.actingCredentialId,
            }
          : {
              ...common,
              authorityMode: "DELEGATED" as const,
              grantorId: authorization.grantorId,
              grantorType: authorization.grantorType,
              grantorCredentialId: authorization.grantorCredentialId,
              delegationId: authorization.delegationId,
              delegationBindingHash: authorization.delegationBindingHash,
            };
        const result = await client.consumeStepUpAuthorization(input);
        setConsumption(result.authorized ? "STEP_UP_AUTHORIZATION_CONSUMED" : "STEP_UP_AUTHORIZATION_REJECTED");
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  const canConsume = receipt !== null || authorization !== null;

  return (
    <main>
      <header className="hero">
        <div>
          <p className="eyebrow">ORDIN · zKYC Core</p>
          <h1>Authority Reference Cockpit</h1>
          <p className="lede">Inspect deterministic action-authority decisions from request to one-time consumption.</p>
        </div>
        <div className="boundary" role="note" aria-label="Reference boundary">
          <strong>REFERENCE ONLY</strong>
          <span>Not KYC, ZK verification, production authentication, or action execution.</span>
        </div>
      </header>

      <section className="panel scenario-panel" aria-labelledby="scenario-heading">
        <div className="section-heading">
          <div>
            <p className="step">01 · REQUEST</p>
            <h2 id="scenario-heading">Select a deterministic case</h2>
          </div>
          <button className="primary" type="button" onClick={() => void evaluateScenario()} disabled={busy !== null}>
            {busy === "evaluate" ? "Evaluating…" : "Evaluate authority"}
          </button>
        </div>
        <div className="scenario-grid">
          {scenarios.map((candidate) => (
            <label className={candidate.id === scenarioId ? "scenario selected" : "scenario"} key={candidate.id}>
              <input
                type="radio"
                name="scenario"
                value={candidate.id}
                checked={candidate.id === scenarioId}
                onChange={() => setScenarioId(candidate.id)}
              />
              <span className={`outcome ${candidate.outcome.toLowerCase()}`}>{candidate.outcome}</span>
              <strong>{candidate.label}</strong>
              <small>{candidate.summary}</small>
            </label>
          ))}
        </div>
      </section>

      {error !== null && <p className="error" role="alert">{error}</p>}

      <div className="work-grid">
        <section className="panel" aria-labelledby="decision-heading">
          <p className="step">02 · DECISION</p>
          <h2 id="decision-heading">Reason-coded result</h2>
          {decision === null ? (
            <p className="empty">Evaluate a case to inspect its bound decision.</p>
          ) : (
            <div className="decision-card">
              <span className={`outcome large ${decision.outcome.toLowerCase()}`}>{decision.outcome}</span>
              <dl>
                <div><dt>Reason</dt><dd>{decision.reasonCode}</dd></div>
                <div><dt>Principal type</dt><dd>{decision.subjectType}</dd></div>
                <div><dt>Authority mode</dt><dd>{decision.authorityMode}</dd></div>
                <div><dt>Acting credential</dt><dd>{decision.actingCredentialId}</dd></div>
                <div><dt>Effective scope</dt><dd className="hash">{decision.effectiveScopeHash}</dd></div>
                <div><dt>Action</dt><dd>{decision.action}</dd></div>
                <div><dt>Tier</dt><dd>{decision.actionSensitivity}</dd></div>
                <div><dt>Resource</dt><dd>{decision.resourceId}</dd></div>
                <div><dt>Policy</dt><dd>{decision.policyId}</dd></div>
                <div><dt>Context</dt><dd className="hash">{decision.contextHash}</dd></div>
              </dl>
              {presentedAuthority === null ? null : (
                <div className="scope-summary" aria-label="Bound authority scope">
                  <h3>Bound scope</h3>
                  <p><strong>Capabilities:</strong> {presentedAuthority.effectiveCapabilities.join(", ")}</p>
                  <p><strong>Actions:</strong> {presentedAuthority.effectiveActions.join(", ")}</p>
                  <p><strong>Resources:</strong> {presentedAuthority.effectiveResources.join(", ")}</p>
                  {presentedAuthority.delegation === undefined ? null : (
                    <div aria-label="Delegation binding">
                      <h3>Delegation binding</h3>
                      <p><strong>Grantor:</strong> {presentedAuthority.delegation.grantorId} / {presentedAuthority.delegation.grantorType}</p>
                      <p><strong>Delegation:</strong> {presentedAuthority.delegation.id}</p>
                      <p className="hash"><strong>Binding:</strong> {presentedAuthority.delegation.delegationBindingHash}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="resolution-heading">
          <p className="step">03 · RESOLUTION</p>
          <h2 id="resolution-heading">Human boundary</h2>
          {stepUpRequest === null ? (
            <p className="empty">Only STEP_UP cases open a human resolution request.</p>
          ) : (
            <div>
              <p className="request-id">{stepUpRequest.id}</p>
              <div className="button-row">
                <button
                  type="button"
                  onClick={() => void resolveStepUp("APPROVE")}
                  disabled={busy !== null || resolutionReason !== null}
                >Approve</button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => void resolveStepUp("REJECT")}
                  disabled={busy !== null || resolutionReason !== null}
                >Reject</button>
              </div>
              {resolutionReason !== null && <p className="result-line">{resolutionReason}</p>}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="consume-heading">
          <p className="step">04 · CONSUMPTION</p>
          <h2 id="consume-heading">One-time authority</h2>
          <p className="empty">Verification and nonce consumption happen before any downstream handoff. No protected action runs here.</p>
          <button type="button" onClick={() => void consumeAuthority()} disabled={!canConsume || busy !== null}>
            {busy === "consume" ? "Consuming…" : "Verify and consume once"}
          </button>
          {consumption !== null && <p className="result-line">{consumption}</p>}
        </section>
      </div>

      <section className="panel log-panel" aria-labelledby="log-heading">
        <div className="section-heading">
          <div>
            <p className="step">05 · REFERENCE LOG</p>
            <h2 id="log-heading">Reason-coded in-memory entries</h2>
          </div>
          <button className="secondary" type="button" onClick={() => void refreshLogSafely()} disabled={busy !== null}>Refresh</button>
        </div>
        <p className="log-boundary">Defensive-copy reference records only—not durable or distributed audit storage.</p>
        {entries.length === 0 ? (
          <p className="empty">No decisions recorded in this process.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Outcome</th><th>Reason</th><th>Receipt</th><th>Action</th><th>Policy</th></tr></thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id}>
                    <td>{entry.id}</td>
                    <td><span className={`outcome ${entry.decision.outcome.toLowerCase()}`}>{entry.decision.outcome}</span></td>
                    <td>{entry.decision.reasonCode}</td>
                    <td>{entry.receipt === undefined ? "—" : "HMAC summary"}</td>
                    <td>{entry.decision.action}</td>
                    <td>{entry.decision.policyId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
