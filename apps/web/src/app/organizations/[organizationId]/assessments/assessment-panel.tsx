"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../../../lib/secure-client";

type Assessment = components["schemas"]["AssessmentResponse"];
type Domain = components["schemas"]["DomainResponse"];
type Step = components["schemas"]["AssessmentStepResponse"];

/** Runs still doing work are polled; settled ones are left alone. */
const POLL_INTERVAL_MS = 4000;
const LIVE_STATES = new Set([
  "queued",
  "planning",
  "collecting",
  "normalizing",
  "evaluating",
  "agent_analysis",
  "report_generation",
]);

/** Settled runs. Anything here has whatever findings it is ever going to have. */
const TERMINAL_STATES = new Set([
  "completed",
  "partially_completed",
  "failed",
  "cancelled",
  "expired",
  "blocked_by_policy",
]);

const STATE_LABELS: Record<string, string> = {
  draft: "Ciornă",
  awaiting_authorization: "Așteaptă autorizarea",
  queued: "În așteptare",
  planning: "Planificare",
  collecting: "Colectare dovezi",
  normalizing: "Normalizare",
  evaluating: "Evaluare",
  agent_analysis: "Analiză asistată",
  report_generation: "Generare raport",
  completed: "Finalizată",
  partially_completed: "Finalizată parțial",
  cancelled: "Anulată",
  failed: "Eșuată",
  expired: "Expirată",
  blocked_by_policy: "Blocată de politică",
};

/**
 * Below this much coverage the methodology replaces the band rather than the number,
 * so that a thin assessment cannot be presented as a confident result. Mirrors
 * `minimum_coverage_percentage` in the policy catalog.
 */
const COVERAGE_FLOOR_PERCENTAGE = 60;

type AssessmentMode = Assessment["mode"];
const PASSIVE = "passive_observation" satisfies AssessmentMode;
const AUTHORIZED = "authorized_assessment" satisfies AssessmentMode;

/** Checks in the published catalog. Every one of them is reachable passively. */
const TOTAL_CHECKS = 22;

const MODE_LABELS: Record<AssessmentMode, string> = {
  passive_observation: "Observare publică",
  authorized_assessment: "Evaluare autorizată",
};

const INSUFFICIENT_COVERAGE = "insufficient_coverage";

const BAND_LABELS: Record<string, string> = {
  resilient: "Rezilient",
  managed: "Gestionat",
  developing: "În dezvoltare",
  exposed: "Expus",
  critical: "Critic",
  [INSUFFICIENT_COVERAGE]: "Dovezi insuficiente",
};

const STEP_LABELS: Record<string, string> = {
  pending: "în așteptare",
  running: "în curs",
  succeeded: "reușit",
  failed: "eșuat",
  skipped: "omis",
  cancelled: "anulat",
  dead_lettered: "abandonat",
};

function toneFor(state: string): string {
  if (state === "completed") return "success";
  if (state === "partially_completed") return "warning";
  if (["failed", "cancelled", "expired", "blocked_by_policy"].includes(state)) return "danger";
  return "neutral";
}

function stepTone(state: Step["state"]): string {
  if (state === "succeeded") return "success";
  if (state === "failed" || state === "dead_lettered") return "danger";
  if (state === "skipped" || state === "cancelled") return "neutral";
  if (state === "running") return "info";
  return "neutral";
}

export default function AssessmentPanel({ organizationId }: { organizationId: string }) {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [message, setMessage] = useState("Încărcăm evaluările…");
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const reload = useCallback(async () => {
    await loadSession();
    const [nextAssessments, nextDomains] = await Promise.all([
      apiRequest<Assessment[]>(`/api/v1/organizations/${organizationId}/assessments`),
      apiRequest<Domain[]>(`/api/v1/organizations/${organizationId}/domains`),
    ]);
    setAssessments(nextAssessments);
    setDomains(nextDomains);
    setMessage("");
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(error instanceof ApiError ? error.message : "Starea nu a putut fi încărcată."),
    );
  }, [reload]);

  // Poll only while something is genuinely running. A settled run cannot change,
  // so continuing to poll would be noise for the reader and load for the server.
  useEffect(() => {
    const live = assessments.some((item) => LIVE_STATES.has(item.state));
    if (!live) return;
    timer.current = setTimeout(() => {
      reload().catch(() => undefined);
    }, POLL_INTERVAL_MS);
    return () => clearTimeout(timer.current);
  }, [assessments, reload]);

  async function start(domainId: string, mode: AssessmentMode) {
    setBusy(true);
    setMessage(
      mode === PASSIVE
        ? "Punem observarea în coadă…"
        : "Punem evaluarea autorizată în coadă…",
    );
    try {
      await apiRequest<Assessment>(`/api/v1/organizations/${organizationId}/assessments`, {
        method: "POST",
        body: JSON.stringify({ domain_id: domainId, mode }),
      });
      await reload();
      setMessage(
        mode === PASSIVE
          ? "Observarea a fost pusă în coadă. Citim doar date deja publice."
          : "Evaluarea autorizată a fost pusă în coadă.",
      );
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Evaluarea nu a putut fi pornită.");
    } finally {
      setBusy(false);
    }
  }

  async function cancel(assessmentId: string) {
    setBusy(true);
    try {
      await apiRequest<Assessment>(
        `/api/v1/organizations/${organizationId}/assessments/${assessmentId}/cancel`,
        { method: "POST", body: JSON.stringify({ reason: "Anulată din interfață" }) },
      );
      await reload();
      setMessage("Anularea a fost cerută; lucrul în curs se oprește la următorul punct sigur.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Anularea nu a putut fi cerută.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="assessments-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Evaluări</p>
          <h1 id="assessments-title">Evaluări ale suprafeței externe</h1>
        </div>
      </div>

      <h2>Pornește o evaluare</h2>
      {/*
        Two modes, offered side by side rather than one gated behind the other,
        because what each does is genuinely different -- and because requiring proof
        of control for reading published data would be a ceremony that protects
        nobody while putting the whole methodology out of reach of anyone evaluating
        a domain they do not run.
      */}
      <p className="hint">
        <strong>Observarea publică</strong> citește doar ce publică deja domeniul: DNS,
        RDAP, Certificate Transparency, certificatul TLS și pagina pe care o vede orice
        vizitator. Nu cere dovada controlului, pentru că nu cere domeniului nimic în
        plus față de ce oferă tuturor. Acoperă toate cele {TOTAL_CHECKS} verificări ale
        metodologiei.
      </p>
      <p className="hint">
        <strong>Evaluarea autorizată</strong> poate trece dincolo de ce vede un
        vizitator, așa că cere control verificat și o autorizare semnată.
      </p>

      {domains.length === 0 ? (
        <p className="hint">Adaugă mai întâi un domeniu.</p>
      ) : (
        <ul className="card-list">
          {domains.map((domain) => {
            const verified = domain.ownership_state === "verified";
            return (
              <li key={domain.id} className="domain-run-row">
                <span>
                  {domain.unicode_display}
                  {!verified && (
                    <small className="muted"> · control neverificat</small>
                  )}
                </span>
                <span className="run-actions">
                  <button
                    type="button"
                    className="button primary"
                    disabled={busy}
                    onClick={() => start(domain.id, PASSIVE)}
                  >
                    Observă public
                  </button>
                  <button
                    type="button"
                    className="button secondary"
                    disabled={busy || !verified}
                    onClick={() => start(domain.id, AUTHORIZED)}
                    /*
                      Disabled controls explain themselves. A button that is simply
                      inert teaches nothing, and the reason here is the whole point of
                      the distinction.
                    */
                    title={
                      verified
                        ? undefined
                        : "Necesită control verificat asupra domeniului."
                    }
                  >
                    Evaluare autorizată
                  </button>
                </span>
              </li>
            );
          })}
        </ul>
      )}

      <h2>Evaluări recente</h2>
      {assessments.length === 0 ? (
        <p className="hint">Nicio evaluare încă.</p>
      ) : (
        <ul className="card-list">
          {assessments.map((assessment) => (
            <li key={assessment.id} className="assessment-card">
              <div>
                <span className={`badge ${toneFor(assessment.state)}`}>
                  {STATE_LABELS[assessment.state] ?? assessment.state}
                </span>
                <p className="muted">
                  {/*
                    The mode sits next to the result, not in a detail panel: a score
                    cannot be read honestly without knowing what the run was permitted
                    to look at.
                  */}
                  {MODE_LABELS[assessment.mode] ?? assessment.mode} · Metodologia{" "}
                  {assessment.methodology_version} ·{" "}
                  {new Date(assessment.created_at).toLocaleString("ro-RO")}
                </p>
              </div>

              <div className="assessment-progress">
                {/*
                  The value is the number of steps that have actually settled, so a slow
                  run shows slow progress rather than a reassuring animation.
                */}
                <progress
                  max={assessment.progress.total_steps}
                  value={assessment.progress.settled_steps}
                  aria-labelledby={`progress-label-${assessment.id}`}
                />
                <p id={`progress-label-${assessment.id}`} className="muted">
                  {assessment.progress.settled_steps} din {assessment.progress.total_steps} etape
                  ({assessment.progress.percentage}%)
                  {(assessment.progress.failed_steps ?? []).length > 0 &&
                    ` · ${(assessment.progress.failed_steps ?? []).length} eșuate`}
                </p>
              </div>

              {assessment.score !== null &&
                assessment.score !== undefined &&
                (assessment.band === INSUFFICIENT_COVERAGE ? (
                  /*
                    Below the coverage floor the number is not a result, and showing it
                    as one is the single most misleading thing this screen could do: a
                    run that observed almost nothing would read as a perfect score. The
                    methodology replaces the band precisely so a thin assessment cannot
                    be presented as a confident one, so the reader gets the reason
                    instead, and the number only as an audit detail.
                  */
                  <div className="assessment-score insufficient">
                    <p className="score-verdict">Dovezi insuficiente pentru un scor</p>
                    <p className="muted">
                      Am putut evalua doar {assessment.coverage_percentage}% din verificări.
                      Sub pragul de {COVERAGE_FLOOR_PERCENTAGE}% rezultatul nu este
                      reprezentativ, așa că nu îl prezentăm ca scor.
                    </p>
                    <p className="muted small">
                      Valoare brută, pentru audit: {assessment.score} / 100
                    </p>
                  </div>
                ) : (
                  <div className="assessment-score">
                    <p className="score-verdict">
                      <strong>{assessment.score}</strong> / 100 ·{" "}
                      {BAND_LABELS[assessment.band ?? ""] ?? assessment.band}
                    </p>
                    <p className="muted">Acoperire {assessment.coverage_percentage}%</p>
                  </div>
                ))}

              {/*
                A score is not actionable on its own. The link is offered on every
                settled run, including one below the coverage floor: what little was
                found there is still worth reading, and is often the reason coverage
                was low.
              */}
              {TERMINAL_STATES.has(assessment.state) && (
                <a
                  className="button secondary"
                  href={`/organizations/${organizationId}/domains/${assessment.domain_id}/findings`}
                >
                  Vezi constatările
                </a>
              )}

              {(assessment.steps ?? []).length > 0 && (
                <details>
                  <summary>Etape ({(assessment.steps ?? []).length})</summary>
                  <ul className="step-list">
                    {(assessment.steps ?? []).map((step) => (
                      <li key={step.name}>
                        <span className={`badge ${stepTone(step.state)}`}>
                          {STEP_LABELS[step.state] ?? step.state}
                        </span>
                        <code>{step.name}</code>
                        {step.last_error && <small className="muted">{step.last_error}</small>}
                      </li>
                    ))}
                  </ul>
                </details>
              )}

              {LIVE_STATES.has(assessment.state) && !assessment.cancellation_requested && (
                <button
                  type="button"
                  className="button secondary"
                  disabled={busy}
                  onClick={() => cancel(assessment.id)}
                >
                  Anulează
                </button>
              )}
              {assessment.cancellation_requested && (
                <p className="muted">Anulare cerută; se oprește la următorul punct sigur.</p>
              )}
            </li>
          ))}
        </ul>
      )}

      <p className="status" role="status" aria-live="polite">
        {message}
      </p>
    </section>
  );
}
