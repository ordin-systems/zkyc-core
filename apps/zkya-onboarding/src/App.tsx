import { useMemo, useState } from "react";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type AccessDecision,
  type OnboardingView,
  type ReceiptExpectedBinding,
} from "@ordin/zkyc-sdk-reference";
import {
  executeScenario,
  refreshOnboardingView,
  scenarios,
  type OnboardingClient,
  type ScenarioExecution,
} from "./scenarios.js";

const defaultClient = new ZkycReferenceClient({ baseUrl: "/api/" });

export interface AppProps {
  readonly client?: OnboardingClient;
  readonly initialView?: OnboardingView | null;
}

function future(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function errorMessage(error: unknown): string {
  if (error instanceof ZkycApiError) {
    return `API request failed closed · ${error.code} · HTTP ${error.status}`;
  }
  if (error instanceof ZkycTransportError) {
    return error.code === "INVALID_RESPONSE"
      ? "Malformed API response rejected by the SDK runtime contract."
      : "Reference API transport is unavailable. No authority state was inferred.";
  }
  return "Reference flow failed closed. No authority state was inferred.";
}

function receiptExpectedBinding(decision: AccessDecision): ReceiptExpectedBinding {
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
    if (decision.credentialId === undefined) {
      throw new Error("direct receipt decision is missing its credential binding");
    }
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

function tone(value: string): string {
  if (["ACTIVE", "ELIGIBLE", "ALLOW", "APPROVED", "UNCONSUMED", "CONSUMED"].includes(value)) {
    return "positive";
  }
  if (["PENDING", "APPROVAL_REQUIRED", "STEP_UP"].includes(value)) return "pending";
  if (["REVOKED", "EXPIRED", "INVALID", "INELIGIBLE", "DENY", "REJECTED"].includes(value)) {
    return "negative";
  }
  return "neutral";
}

function TokenList({ values, empty = "None" }: { readonly values: readonly string[]; readonly empty?: string }) {
  if (values.length === 0) return <span className="quiet">{empty}</span>;
  return (
    <ul className="token-list">
      {values.map((value) => <li key={value}>{value}</li>)}
    </ul>
  );
}

function Fact({ label, value, mono = false }: {
  readonly label: string;
  readonly value: string;
  readonly mono?: boolean;
}) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </div>
  );
}

export function App({ client = defaultClient, initialView = null }: AppProps = {}) {
  const [scenarioId, setScenarioId] = useState(scenarios[0]?.id ?? "");
  const [execution, setExecution] = useState<ScenarioExecution | null>(null);
  const [view, setView] = useState<OnboardingView | null>(initialView);
  const [busy, setBusy] = useState<"run" | "refresh" | "resolve" | "consume" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resolutionResult, setResolutionResult] = useState<string | null>(null);
  const [consumeResults, setConsumeResults] = useState<readonly string[]>([]);

  const scenario = useMemo(
    () => scenarios.find((candidate) => candidate.id === scenarioId) ?? scenarios[0],
    [scenarioId],
  );

  async function loadView(logId: string): Promise<void> {
    const refreshed = await refreshOnboardingView(client, logId);
    setView(refreshed);
  }

  async function runScenario(): Promise<void> {
    if (scenario === undefined) return;
    setBusy("run");
    setError(null);
    setExecution(null);
    setView(null);
    setResolutionResult(null);
    setConsumeResults([]);
    try {
      const result = await executeScenario(scenario.id, client);
      setExecution(result);
      await loadView(result.logId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function refresh(): Promise<void> {
    if (execution === null) return;
    setBusy("refresh");
    setError(null);
    try {
      await loadView(execution.logId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function resolve(resolution: "APPROVE" | "REJECT"): Promise<void> {
    const currentExecution = execution;
    if (currentExecution === null || currentExecution.stepUpRequest === undefined) return;
    const request = currentExecution.stepUpRequest;
    setBusy("resolve");
    setError(null);
    setResolutionResult(null);
    try {
      const approver = {
        id: "human:reference-approver",
        type: "HUMAN",
        affiliations: [{ organizationId: "organization:ordin-reference", role: "reviewer" }],
      } as const;
      const { credential } = await client.issueCredential({
        principal: approver,
        capabilities: [request.requiredApproverCapability],
        allowedActions: ["step-up:resolve"],
        allowedResourceIds: [request.resourceId],
        expiresAt: future(30),
      });
      const result = await client.resolveStepUpRequest(request.id, {
        resolution,
        approver,
        approverCredential: credential,
      });
      setResolutionResult(result.ok ? "STEP_UP_APPROVED" : result.reasonCode);
      await loadView(currentExecution.logId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function consumeReceipt(): Promise<void> {
    if (execution?.receipt === undefined) return;
    setBusy("consume");
    setError(null);
    try {
      const result = await client.consumeReceipt({
        receipt: execution.receipt,
        expected: receiptExpectedBinding(execution.decision),
      });
      setConsumeResults((current) => [...current, result.reasonCode]);
      await loadView(execution.logId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  const isPendingStepUp = view?.requiredApproval.status === "PENDING" &&
    execution?.stepUpRequest !== undefined;

  return (
    <main className="page-shell">
      <header className="masthead">
        <div className="masthead-meta" aria-label="Artifact identity">
          <span>ORDIN SYSTEMS</span>
          <span>REFERENCE / v0.3.0</span>
          <span>LOCAL PROCESS</span>
        </div>
        <div className="hero-grid">
          <div>
            <p className="eyebrow">Executable authority-state specimen</p>
            <h1>zkYA / Know-Your-Agent Onboarding Reference</h1>
            <p className="lede">
              A deterministic reading surface for principal identity, delegated authority,
              human approval, and one-time receipt state.
            </p>
          </div>
          <div className="hero-mark" aria-hidden="true">
            <span>zk</span>
            <strong>YA</strong>
          </div>
        </div>
      </header>

      <aside className="boundary" aria-label="Persistent reference boundary">
        <strong>LOCAL REFERENCE ONLY</strong>
        <p>
          Not real KYC/AML, ZK-proof verification, production authentication or deployment,
          protected execution, or evidence of autonomous-agent trustworthiness.
        </p>
      </aside>

      <section className="scenario-section" aria-labelledby="scenario-heading">
        <div className="section-intro">
          <p className="folio">I · SYNTHETIC CASES</p>
          <h2 id="scenario-heading">Choose an authority path</h2>
          <p>Each case is created through the browser SDK against the clean in-memory API process.</p>
        </div>
        <fieldset className="scenario-list">
          <legend className="sr-only">Reference scenario</legend>
          {scenarios.map((candidate) => (
            <label
              className={candidate.id === scenarioId ? "scenario-option selected" : "scenario-option"}
              key={candidate.id}
            >
              <input
                type="radio"
                name="reference-scenario"
                value={candidate.id}
                checked={candidate.id === scenarioId}
                onChange={() => setScenarioId(candidate.id)}
              />
              <span className="scenario-index">{candidate.index}</span>
              <span className="scenario-copy">
                <strong>{candidate.label}</strong>
                <small>{candidate.summary}</small>
              </span>
              <span className={`status-chip ${tone(candidate.expected)}`}>{candidate.expected}</span>
            </label>
          ))}
        </fieldset>
        <div className="run-row">
          <div>
            <span className="run-label">Selected path</span>
            <strong>{scenario?.label}</strong>
          </div>
          <button className="primary-button" type="button" onClick={() => void runScenario()} disabled={busy !== null}>
            {busy === "run" ? "Running SDK sequence…" : "Run reference scenario"}
          </button>
        </div>
      </section>

      <div className="announcer" aria-live="polite" aria-atomic="true">
        {busy === null ? "" : `Reference operation in progress: ${busy}`}
      </div>
      {error === null ? null : <p className="error-banner" role="alert" aria-live="assertive">{error}</p>}

      {view === null ? (
        <section className="empty-state" aria-labelledby="empty-heading">
          <p className="folio">II · RETAINED VIEW</p>
          <h2 id="empty-heading">No onboarding state retained yet</h2>
          <p>Run a synthetic case to request a server-derived onboarding view. The browser never authors status labels.</p>
        </section>
      ) : (
        <section className="view-section" aria-labelledby="view-heading" data-testid="onboarding-view">
          <div className="view-heading">
            <div>
              <p className="folio">II · RETAINED VIEW</p>
              <h2 id="view-heading">Bound authority record</h2>
            </div>
            <div className="view-actions">
              <span className={`status-chip large ${tone(view.verificationStatus)}`}>
                {view.verificationStatus}
              </span>
              <button className="text-button" type="button" onClick={() => void refresh()} disabled={busy !== null || execution === null}>
                {busy === "refresh" ? "Refreshing…" : "Refresh retained view"}
              </button>
            </div>
          </div>

          <div className="identity-spread">
            <article className="paper-card principal-card" aria-labelledby="principal-heading">
              <p className="card-number">01</p>
              <h3 id="principal-heading">Principal</h3>
              <dl className="fact-list">
                <Fact label="Principal ID" value={view.principal.id} mono />
                <Fact label="Principal type" value={view.principal.type} />
                <Fact label="Verification" value={view.verificationStatus} />
                <Fact label="Authority mode" value={view.authorityMode} />
              </dl>
              <div className="subsection">
                <h4>Affiliations · {view.principal.affiliations.length}</h4>
                {view.principal.affiliations.length === 0 ? (
                  <p className="quiet">No affiliations retained for this principal.</p>
                ) : (
                  <ul className="affiliation-list">
                    {view.principal.affiliations.map((affiliation) => (
                      <li key={`${affiliation.organizationId}:${affiliation.role}`}>
                        <strong>{affiliation.organizationId}</strong>
                        <span>{affiliation.role}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </article>

            <article className="paper-card authority-card" aria-labelledby="authority-heading">
              <p className="card-number">02</p>
              <h3 id="authority-heading">Authority</h3>
              {view.delegatedScope === null ? (
                <div className="direct-statement">
                  <span className="status-chip neutral">DIRECT</span>
                  <p>Authority is bound to the acting principal's registered credential; no grantor scope is presented.</p>
                </div>
              ) : (
                <>
                  <dl className="fact-list compact">
                    <Fact label="Delegation ID" value={view.delegatedScope.delegationId} mono />
                    <Fact label="Grantor ID" value={view.delegatedScope.grantorId} mono />
                    <Fact label="Grantor type" value={view.delegatedScope.grantorType} />
                    <Fact label="Delegation status" value={view.delegatedScope.status} />
                  </dl>
                  <div className="scope-columns">
                    <div><h4>Capabilities</h4><TokenList values={view.delegatedScope.capabilities} /></div>
                    <div><h4>Exact actions</h4><TokenList values={view.delegatedScope.allowedActions} /></div>
                    <div><h4>Exact resources</h4><TokenList values={view.delegatedScope.allowedResourceIds} /></div>
                  </div>
                </>
              )}
            </article>
          </div>

          <div className="state-grid">
            <article className="paper-card eligibility-card" aria-labelledby="eligibility-heading">
              <p className="card-number">03</p>
              <h3 id="eligibility-heading">Eligible authority</h3>
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Action</th><th>Resource</th><th>Status</th><th>Reason</th></tr></thead>
                  <tbody>
                    {view.eligibleActions.map((eligible) => (
                      <tr key={`${eligible.action}:${eligible.resourceId}`}>
                        <td className="mono">{eligible.action}</td>
                        <td className="mono">{eligible.resourceId}</td>
                        <td><span className={`status-chip ${tone(eligible.status)}`}>{eligible.status}</span></td>
                        <td className="reason">{eligible.reasonCode}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>

            <article className="paper-card approval-card" aria-labelledby="approval-heading">
              <p className="card-number">04</p>
              <h3 id="approval-heading">Human approval</h3>
              <span className={`status-chip large ${tone(view.requiredApproval.status)}`}>
                {view.requiredApproval.status}
              </span>
              <p className="micro-id">{view.requiredApproval.requestId ?? "No request issued"}</p>
              {isPendingStepUp ? (
                <div className="button-pair">
                  <button type="button" onClick={() => void resolve("APPROVE")} disabled={busy !== null}>Approve as HUMAN</button>
                  <button className="secondary-button" type="button" onClick={() => void resolve("REJECT")} disabled={busy !== null}>Reject as HUMAN</button>
                </div>
              ) : null}
              {resolutionResult === null ? null : (
                <p className="result-line" role="status" aria-live="polite">{resolutionResult}</p>
              )}
              <p className="card-note">Resolution issues a fresh HUMAN credential with the exact approver capability, <code>step-up:resolve</code>, and original resource.</p>
            </article>

            <article className="paper-card receipt-card" aria-labelledby="receipt-heading">
              <p className="card-number">05</p>
              <h3 id="receipt-heading">Signed receipt</h3>
              <span className={`status-chip large ${tone(view.receipt.status)}`}>{view.receipt.status}</span>
              {execution?.receipt === undefined ? (
                <p className="quiet">No authorizing signed receipt was issued for this decision lane.</p>
              ) : (
                <>
                  <dl className="fact-list compact receipt-facts">
                    <Fact label="Algorithm" value={execution.receipt.algorithm} />
                    <Fact label="Payload version" value={`v${execution.receipt.payload.version}`} />
                    <Fact label="Bound subject" value={`${execution.receipt.payload.subjectId} / ${execution.receipt.payload.subjectType}`} mono />
                    <Fact label="Bound action" value={execution.receipt.payload.action} mono />
                    <Fact label="Bound resource" value={execution.receipt.payload.resourceId} mono />
                    <Fact label="Bound state" value={`${execution.receipt.payload.authorityMode} · ${execution.receipt.payload.decision}`} />
                  </dl>
                  <button type="button" onClick={() => void consumeReceipt()} disabled={busy !== null}>
                    {busy === "consume" ? "Verifying full v2 binding…" : "Verify & consume full v2 binding"}
                  </button>
                </>
              )}
              {consumeResults.length === 0 ? null : (
                <ol className="consume-history" aria-live="polite" aria-label="Receipt consume attempts">
                  {consumeResults.map((result, index) => (
                    <li key={`${index}:${result}`}>
                      <span>Attempt {index + 1}</span>
                      <strong className={result === "RECEIPT_VALID" ? "positive-text" : "negative-text"}>{result}</strong>
                    </li>
                  ))}
                </ol>
              )}
            </article>
          </div>

          <footer className="policy-strip">
            <div><span>Decision log</span><strong>{view.decisionLogId}</strong></div>
            <div><span>Policy</span><strong>{view.policyId}</strong></div>
            <div><span>Policy version</span><strong>{view.policyVersion}</strong></div>
          </footer>
        </section>
      )}

      <footer className="page-footer">
        <span>REFERENCE ARTIFACT · IN-MEMORY STATE · NO PROTECTED ACTION EXECUTION</span>
        <span>zkYA / 2026</span>
      </footer>
    </main>
  );
}
