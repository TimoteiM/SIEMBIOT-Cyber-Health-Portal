"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import type { MessageKey, Translator } from "../../../../../../lib/i18n";
import { useLocalization } from "../../../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../../../lib/api-errors";
import { apiRequest, loadSession } from "../../../../../../lib/secure-client";

type DomainFindings = components["schemas"]["DomainFindingsResponse"];
type Finding = components["schemas"]["FindingResponse"];
type Severity = Finding["severity"];

/** Most urgent first. Matches the server's order; the client never re-sorts. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

const COVERAGE_FLOOR_PERCENTAGE = 60;
const INSUFFICIENT_COVERAGE = "insufficient_coverage";

/**
 * Severity is carried by the word first and the tone second. Somebody reading this in
 * greyscale, or who cannot distinguish red from green, has to get the same ordering as
 * everyone else -- so the label is never decoration on top of a colour.
 */
function severityTone(severity: Severity): string {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "neutral";
}

function confidenceNote(finding: Finding, t: Translator): string | null {
  const { attribution, source, freshness } = finding.confidence;
  const weakest = Math.min(attribution, source, freshness);
  if (weakest >= 1) return null;
  // Named individually rather than averaged: "we are sure about evidence for an asset
  // that may not be yours" and "this is your asset but the evidence is stale" are
  // different problems, and a single blended number would hide both.
  if (attribution === weakest)
    return t("findings.confidenceAttribution", { percent: Math.round(attribution * 100) });
  if (freshness === weakest)
    return t("findings.confidenceFreshness", { percent: Math.round(freshness * 100) });
  return t("findings.confidenceSource", { percent: Math.round(source * 100) });
}

/**
 * How long this has been true, phrased the way somebody would say it. "de 0 zile" is
 * technically correct and reads like a bug; a first sighting today is "azi".
 */
function seenFor(iso: string, t: Translator): string {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days <= 0) return t("findings.seenToday");
  if (days === 1) return t("findings.seenYesterday");
  return t("findings.seenDays", { count: days });
}

export default function FindingsPanel({
  organizationId,
  domainId,
}: {
  organizationId: string;
  domainId: string;
}) {
  const [data, setData] = useState<DomainFindings | null>(null);
  const [message, setMessage] = useState<MessageKey | null>("findings.loading");
  const [includeResolved, setIncludeResolved] = useState(false);
  const { t, formatNumber, pick } = useLocalization();

  const reload = useCallback(
    async (resolved: boolean) => {
      await loadSession();
      const next = await apiRequest<DomainFindings>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/findings` +
          `?include_resolved=${resolved}`,
      );
      setData(next);
      setMessage(null);
    },
    [organizationId, domainId],
  );

  useEffect(() => {
    reload(includeResolved).catch((error: unknown) =>
      setMessage(apiErrorKey(error, "findings.loadFailed")),
    );
  }, [reload, includeResolved]);

  const findings = data?.findings ?? [];
  const grouped = SEVERITY_ORDER.map((severity) => ({
    severity,
    items: findings.filter((item) => item.severity === severity),
  })).filter((group) => group.items.length > 0);

  const insufficient = data?.band === INSUFFICIENT_COVERAGE;

  return (
    <section className="panel" aria-labelledby="findings-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("findings.eyebrow")}</p>
          <h1 id="findings-title">{t("findings.title")}</h1>
        </div>
      </div>

      {data && (
        <div className="findings-header">
          {/*
            The score sits with the coverage it was drawn from. A list of weaknesses
            shown on its own invites the reader to assume it is the complete list, and
            below the coverage floor it certainly is not.
          */}
          {insufficient ? (
            <div className="assessment-score insufficient">
              <p className="score-verdict">{t("assessments.insufficientTitle")}</p>
              <p className="muted">
                {t("findings.insufficientBody", {
                  percent: formatNumber(data.coverage_percentage ?? 0),
                  floor: COVERAGE_FLOOR_PERCENTAGE,
                })}
              </p>
            </div>
          ) : data.score !== null && data.score !== undefined ? (
            <div className="assessment-score">
              <p className="score-verdict">
                <strong>{formatNumber(data.score ?? 0)}</strong> / 100 ·{" "}
                {t(`band.${data.band}` as MessageKey)}
              </p>
              <p className="muted">
                {(data.coverage_percentage ?? 100) < 100
                  ? t("findings.coverageRemainder", {
                      percent: formatNumber(data.coverage_percentage ?? 0),
                    })
                  : t("assessments.coverage", {
                      percent: formatNumber(data.coverage_percentage ?? 0),
                    })}
              </p>
            </div>
          ) : (
            <p className="hint">{t("findings.noAssessment")}</p>
          )}

          <ul className="severity-summary" aria-label={t("findings.bySeverity")}>
            {SEVERITY_ORDER.map((severity) => (
              <li key={severity}>
                <span className={`badge ${severityTone(severity)}`}>
                  {t(`severity.${severity}` as MessageKey)}
                </span>
                <strong>{data.summary.by_severity[severity] ?? 0}</strong>
              </li>
            ))}
          </ul>
        </div>
      )}

      <label className="toggle-row">
        <input
          type="checkbox"
          checked={includeResolved}
          onChange={(event) => setIncludeResolved(event.target.checked)}
        />
        <span>{t("findings.showResolved")}</span>
      </label>

      {data && findings.length === 0 && (
        <p className="hint">
          {data.assessment_id
            ? t("findings.none")
            : t("findings.noData")}
        </p>
      )}

      {grouped.map((group) => (
        <section key={group.severity} aria-labelledby={`severity-${group.severity}`}>
          <h2 id={`severity-${group.severity}`}>
            {t("findings.group", {
              severity: t(`severity.${group.severity}` as MessageKey),
              count: group.items.length,
            })}
          </h2>
          <ul className="card-list">
            {group.items.map((finding) => {
              const confidence = confidenceNote(finding, t);
              return (
                <li key={finding.id} className="finding-card">
                  <div className="finding-head">
                    <span className={`badge ${severityTone(finding.severity)}`}>
                      {t(`severity.${finding.severity}` as MessageKey)}
                    </span>
                    <h3>{pick(finding.title_ro, finding.title_en)}</h3>
                  </div>

                  <p className="muted">{pick(finding.rationale_ro, finding.rationale_en)}</p>

                  <dl className="finding-meta">
                    <div>
                      <dt>{t("findings.pillar")}</dt>
                      <dd>
                        {finding.pillar_letter} ·{" "}
                        {t(`pillar.${finding.pillar}` as MessageKey)}
                      </dd>
                    </div>
                    <div>
                      <dt>{t("findings.state")}</dt>
                      <dd>{t(`findingState.${finding.state}` as MessageKey)}</dd>
                    </div>
                    <div>
                      <dt>{t("findings.seen")}</dt>
                      {/*
                        How long this has been true, not just when we last looked. A
                        weakness present for months is a different conversation from
                        one that appeared yesterday.
                      */}
                      <dd>{seenFor(finding.first_seen_at, t)}</dd>
                    </div>
                    <div>
                      <dt>{t("findings.evidence")}</dt>
                      <dd>{finding.evidence_count}</dd>
                    </div>
                  </dl>

                  {confidence && <p className="finding-confidence">⚠ {confidence}</p>}

                  <details>
                    <summary>{t("findings.technicalDetails")}</summary>
                    <dl className="finding-meta">
                      <div>
                        <dt>{t("findings.check")}</dt>
                        <dd>
                          <code>{finding.check_id}</code> v{finding.check_version}
                        </dd>
                      </div>
                      {finding.reason_code && (
                        <div>
                          <dt>{t("findings.reason")}</dt>
                          <dd>
                            <code>{finding.reason_code}</code>
                          </dd>
                        </div>
                      )}
                      <div>
                        <dt>{t("findings.subject")}</dt>
                        <dd>{finding.subject_identifier}</dd>
                      </div>
                      <div>
                        <dt>{t("findings.methodology")}</dt>
                        <dd>{finding.methodology_version}</dd>
                      </div>
                    </dl>
                    {(finding.references ?? []).length > 0 && (
                      <p className="muted">
                        {t("findings.references", {
                          list: (finding.references ?? []).join(", "),
                        })}
                      </p>
                    )}
                    {/*
                      The remediation catalog is not written yet. Naming the template
                      is honest; generating plausible security advice to fill the space
                      would be worse, because a reader cannot tell invented guidance
                      from reviewed guidance and would act on it.
                    */}
                    {finding.remediation_template && (
                      <p className="muted">
                        {t("findings.remediationPending", {
                          template: finding.remediation_template,
                        })}
                      </p>
                    )}
                  </details>
                </li>
              );
            })}
          </ul>
        </section>
      ))}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
