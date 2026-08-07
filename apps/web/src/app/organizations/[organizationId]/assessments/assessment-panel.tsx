"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import type { MessageKey } from "../../../../lib/i18n";
import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type Assessment = components["schemas"]["AssessmentResponse"];
type Domain = components["schemas"]["DomainResponse"];
type Step = components["schemas"]["AssessmentStepResponse"];
type Schedule = components["schemas"]["ScheduleResponse"];
type Cadence = Schedule["cadence"];

const CADENCES: Cadence[] = ["off", "daily", "weekly", "monthly", "quarterly"];
const CADENCE_KEYS = {
  off: "schedule.off",
  daily: "schedule.daily",
  weekly: "schedule.weekly",
  monthly: "schedule.monthly",
  quarterly: "schedule.quarterly",
} as const;

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


const INSUFFICIENT_COVERAGE = "insufficient_coverage";


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
  const [schedules, setSchedules] = useState<Record<string, Schedule>>({});
  const [message, setMessage] = useState<MessageKey | null>("assessments.loading");
  const [busy, setBusy] = useState(false);
  const { t, formatDateTime, formatNumber } = useLocalization();
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const reload = useCallback(async () => {
    await loadSession();
    const [nextAssessments, nextDomains] = await Promise.all([
      apiRequest<Assessment[]>(`/api/v1/organizations/${organizationId}/assessments`),
      apiRequest<Domain[]>(`/api/v1/organizations/${organizationId}/domains`),
    ]);
    setAssessments(nextAssessments);
    setDomains(nextDomains);
    // Fetched per domain rather than as a list: a schedule belongs to a domain, and a
    // separate collection endpoint would be a second place for the same fact to live.
    const loaded = await Promise.all(
      nextDomains.map((domain) =>
        apiRequest<Schedule>(
          `/api/v1/organizations/${organizationId}/domains/${domain.id}/schedule`,
        ).then((schedule) => [domain.id, schedule] as const),
      ),
    );
    setSchedules(Object.fromEntries(loaded));
    setMessage(null);
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(apiErrorKey(error, "assessments.loadFailed")),
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
    setMessage(mode === PASSIVE ? "assessments.queueingPassive" : "assessments.queueingAuthorized");
    try {
      await apiRequest<Assessment>(`/api/v1/organizations/${organizationId}/assessments`, {
        method: "POST",
        body: JSON.stringify({ domain_id: domainId, mode }),
      });
      await reload();
      setMessage(mode === PASSIVE ? "assessments.queuedPassive" : "assessments.queuedAuthorized");
    } catch (error) {
      setMessage(apiErrorKey(error, "assessments.startFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function setCadence(domainId: string, cadence: Cadence) {
    setBusy(true);
    try {
      const saved = await apiRequest<Schedule>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/schedule`,
        { method: "PUT", body: JSON.stringify({ cadence }) },
      );
      setSchedules((current) => ({ ...current, [domainId]: saved }));
      setMessage("schedule.saved");
    } catch (error) {
      setMessage(apiErrorKey(error, "schedule.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function cancel(assessmentId: string) {
    setBusy(true);
    try {
      await apiRequest<Assessment>(
        `/api/v1/organizations/${organizationId}/assessments/${assessmentId}/cancel`,
        { method: "POST", body: JSON.stringify({ reason: t("assessments.cancelReason") }) },
      );
      await reload();
      setMessage("assessments.cancelRequested");
    } catch (error) {
      setMessage(apiErrorKey(error, "assessments.cancelFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="assessments-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("assessments.eyebrow")}</p>
          <h1 id="assessments-title">{t("assessments.title")}</h1>
        </div>
      </div>

      <h2>{t("assessments.startHeading")}</h2>
      {/*
        Two modes, offered side by side rather than one gated behind the other,
        because what each does is genuinely different -- and because requiring proof
        of control for reading published data would be a ceremony that protects
        nobody while putting the whole methodology out of reach of anyone evaluating
        a domain they do not run.
      */}
      <p className="hint">
        <strong>{t("mode.passive_observation")}</strong>{" "}
        {t("assessments.passiveExplainer", { count: TOTAL_CHECKS })}
      </p>
      <p className="hint">
        <strong>{t("mode.authorized_assessment")}</strong>{" "}
        {t("assessments.authorizedExplainer")}
      </p>

      {domains.length === 0 ? (
        <p className="hint">{t("assessments.noDomains")}</p>
      ) : (
        <ul className="card-list">
          {domains.map((domain) => {
            const verified = domain.ownership_state === "verified";
            return (
              <li key={domain.id} className="domain-run-row">
                <span>
                  {domain.unicode_display}
                  {!verified && (
                    <small className="muted"> · {t("assessments.unverified")}</small>
                  )}
                </span>
                {/*
                  The cadence sits beside the one-off buttons because it is the same
                  decision made standing: what should happen to this domain, now and
                  from now on.
                */}
                <label className="cadence-control">
                  <span className="sr-only">{t("schedule.label")}</span>
                  <select
                    value={schedules[domain.id]?.cadence ?? "off"}
                    disabled={busy}
                    onChange={(event) =>
                      setCadence(domain.id, event.target.value as Cadence)
                    }
                  >
                    {CADENCES.map((cadence) => (
                      <option key={cadence} value={cadence}>
                        {t(CADENCE_KEYS[cadence])}
                      </option>
                    ))}
                  </select>
                  {schedules[domain.id]?.next_run_at && (
                    <small className="muted">
                      {t("schedule.nextRun", {
                        when: formatDateTime(schedules[domain.id].next_run_at as string),
                      })}
                    </small>
                  )}
                </label>

                <span className="run-actions">
                  <button
                    type="button"
                    className="button primary"
                    disabled={busy}
                    onClick={() => start(domain.id, PASSIVE)}
                  >
                    {t("assessments.observePublic")}
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
                        : t("assessments.needsVerification")
                    }
                  >
                    {t("assessments.authorizedRun")}
                  </button>
                </span>
              </li>
            );
          })}
        </ul>
      )}

      <h2>{t("assessments.recentHeading")}</h2>
      {assessments.length === 0 ? (
        <p className="hint">{t("assessments.none")}</p>
      ) : (
        <ul className="card-list">
          {assessments.map((assessment) => (
            <li key={assessment.id} className="assessment-card">
              <div>
                <span className={`badge ${toneFor(assessment.state)}`}>
                  {t(`state.${assessment.state}` as MessageKey)}
                </span>
                <p className="muted">
                  {/*
                    The mode sits next to the result, not in a detail panel: a score
                    cannot be read honestly without knowing what the run was permitted
                    to look at.
                  */}
                  {t(`mode.${assessment.mode}` as MessageKey)} ·{" "}
                  {t("assessments.methodology", { version: assessment.methodology_version })} ·{" "}
                  {formatDateTime(assessment.created_at)}
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
                  {t("assessments.progress", {
                    settled: assessment.progress.settled_steps,
                    total: assessment.progress.total_steps,
                    percent: formatNumber(assessment.progress.percentage),
                  })}
                  {(assessment.progress.failed_steps ?? []).length > 0 &&
                    ` · ${t("assessments.failedSteps", {
                      count: (assessment.progress.failed_steps ?? []).length,
                    })}`}
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
                    <p className="score-verdict">{t("assessments.insufficientTitle")}</p>
                    <p className="muted">
                      {t("assessments.insufficientBody", {
                        percent: formatNumber(assessment.coverage_percentage ?? 0),
                        floor: COVERAGE_FLOOR_PERCENTAGE,
                      })}
                    </p>
                    <p className="muted small">
                      {t("assessments.rawScore", { score: formatNumber(assessment.score ?? 0) })}
                    </p>
                  </div>
                ) : (
                  <div className="assessment-score">
                    <p className="score-verdict">
                      <strong>{formatNumber(assessment.score ?? 0)}</strong> / 100 ·{" "}
                      {t(`band.${assessment.band}` as MessageKey)}
                    </p>
                    <p className="muted">
                      {t("assessments.coverage", {
                        percent: formatNumber(assessment.coverage_percentage ?? 0),
                      })}
                    </p>
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
                  {t("assessments.viewFindings")}
                </a>
              )}

              {(assessment.steps ?? []).length > 0 && (
                <details>
                  <summary>{t("assessments.steps", { count: (assessment.steps ?? []).length })}</summary>
                  <ul className="step-list">
                    {(assessment.steps ?? []).map((step) => (
                      <li key={step.name}>
                        <span className={`badge ${stepTone(step.state)}`}>
                          {t(`step.${step.state}` as MessageKey)}
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
                  {t("assessments.cancel")}
                </button>
              )}
              {assessment.cancellation_requested && (
                <p className="muted">{t("assessments.cancelPending")}</p>
              )}
            </li>
          ))}
        </ul>
      )}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
