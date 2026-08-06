"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../../../../../lib/secure-client";

type DomainFindings = components["schemas"]["DomainFindingsResponse"];
type Finding = components["schemas"]["FindingResponse"];
type Severity = Finding["severity"];

/** Most urgent first. Matches the server's order; the client never re-sorts. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critic",
  high: "Ridicat",
  medium: "Mediu",
  low: "Scăzut",
  informational: "Informativ",
};

const STATE_LABELS: Record<Finding["state"], string> = {
  open: "Deschis",
  regressed: "Reapărut",
  resolved: "Rezolvat",
  suppressed: "Suprimat",
  accepted_risk: "Risc acceptat",
};

const BAND_LABELS: Record<string, string> = {
  resilient: "Rezilient",
  managed: "Gestionat",
  developing: "În dezvoltare",
  exposed: "Expus",
  critical: "Critic",
  insufficient_coverage: "Dovezi insuficiente",
};

const PILLAR_LABELS: Record<string, string> = {
  dns: "DNS și delegare",
  email: "Poșta electronică",
  web_tls: "Web și TLS",
  exposure: "Expunere",
  hygiene: "Igienă operațională",
  governance: "Guvernanță",
};

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

function confidenceNote(finding: Finding): string | null {
  const { attribution, source, freshness } = finding.confidence;
  const weakest = Math.min(attribution, source, freshness);
  if (weakest >= 1) return null;
  // Named individually rather than averaged: "we are sure about evidence for an asset
  // that may not be yours" and "this is your asset but the evidence is stale" are
  // different problems, and a single blended number would hide both.
  if (attribution === weakest) return `Atribuire incertă (${Math.round(attribution * 100)}%)`;
  if (freshness === weakest) return `Dovadă mai veche (${Math.round(freshness * 100)}%)`;
  return `Sursă mai puțin sigură (${Math.round(source * 100)}%)`;
}

/**
 * How long this has been true, phrased the way somebody would say it. "de 0 zile" is
 * technically correct and reads like a bug; a first sighting today is "azi".
 */
function seenFor(iso: string): string {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days <= 0) return "azi";
  if (days === 1) return "de ieri";
  return `de ${days} zile`;
}

export default function FindingsPanel({
  organizationId,
  domainId,
}: {
  organizationId: string;
  domainId: string;
}) {
  const [data, setData] = useState<DomainFindings | null>(null);
  const [message, setMessage] = useState("Încărcăm constatările…");
  const [includeResolved, setIncludeResolved] = useState(false);

  const reload = useCallback(
    async (resolved: boolean) => {
      await loadSession();
      const next = await apiRequest<DomainFindings>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/findings` +
          `?include_resolved=${resolved}`,
      );
      setData(next);
      setMessage("");
    },
    [organizationId, domainId],
  );

  useEffect(() => {
    reload(includeResolved).catch((error: unknown) =>
      setMessage(
        error instanceof ApiError ? error.message : "Constatările nu au putut fi încărcate.",
      ),
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
          <p className="eyebrow">Constatări</p>
          <h1 id="findings-title">Ce am găsit</h1>
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
              <p className="score-verdict">Dovezi insuficiente pentru un scor</p>
              <p className="muted">
                Am putut evalua doar {data.coverage_percentage}% din verificări, sub
                pragul de {COVERAGE_FLOOR_PERCENTAGE}%. Lista de mai jos arată ce am
                găsit, dar nu este completă.
              </p>
            </div>
          ) : data.score !== null && data.score !== undefined ? (
            <div className="assessment-score">
              <p className="score-verdict">
                <strong>{data.score}</strong> / 100 ·{" "}
                {BAND_LABELS[data.band ?? ""] ?? data.band}
              </p>
              <p className="muted">
                Acoperire {data.coverage_percentage}%
                {(data.coverage_percentage ?? 100) < 100 &&
                  " — restul verificărilor nu au putut fi evaluate"}
              </p>
            </div>
          ) : (
            <p className="hint">
              Nicio evaluare finalizată pentru acest domeniu. Pornește una din pagina
              Evaluări.
            </p>
          )}

          <ul className="severity-summary" aria-label="Constatări pe severitate">
            {SEVERITY_ORDER.map((severity) => (
              <li key={severity}>
                <span className={`badge ${severityTone(severity)}`}>
                  {SEVERITY_LABELS[severity]}
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
        <span>Arată și constatările rezolvate</span>
      </label>

      {data && findings.length === 0 && (
        <p className="hint">
          {data.assessment_id
            ? "Nicio constatare deschisă pentru acest domeniu."
            : "Nu există încă date pentru acest domeniu."}
        </p>
      )}

      {grouped.map((group) => (
        <section key={group.severity} aria-labelledby={`severity-${group.severity}`}>
          <h2 id={`severity-${group.severity}`}>
            {SEVERITY_LABELS[group.severity]} ({group.items.length})
          </h2>
          <ul className="card-list">
            {group.items.map((finding) => {
              const confidence = confidenceNote(finding);
              return (
                <li key={finding.id} className="finding-card">
                  <div className="finding-head">
                    <span className={`badge ${severityTone(finding.severity)}`}>
                      {SEVERITY_LABELS[finding.severity]}
                    </span>
                    <h3>{finding.title_ro}</h3>
                  </div>

                  <p className="muted">{finding.rationale_ro}</p>

                  <dl className="finding-meta">
                    <div>
                      <dt>Pilon</dt>
                      <dd>
                        {finding.pillar_letter} ·{" "}
                        {PILLAR_LABELS[finding.pillar] ?? finding.pillar}
                      </dd>
                    </div>
                    <div>
                      <dt>Stare</dt>
                      <dd>{STATE_LABELS[finding.state] ?? finding.state}</dd>
                    </div>
                    <div>
                      <dt>Observat</dt>
                      {/*
                        How long this has been true, not just when we last looked. A
                        weakness present for months is a different conversation from
                        one that appeared yesterday.
                      */}
                      <dd>{seenFor(finding.first_seen_at)}</dd>
                    </div>
                    <div>
                      <dt>Dovezi</dt>
                      <dd>{finding.evidence_count}</dd>
                    </div>
                  </dl>

                  {confidence && <p className="finding-confidence">⚠ {confidence}</p>}

                  <details>
                    <summary>Detalii tehnice</summary>
                    <dl className="finding-meta">
                      <div>
                        <dt>Verificare</dt>
                        <dd>
                          <code>{finding.check_id}</code> v{finding.check_version}
                        </dd>
                      </div>
                      {finding.reason_code && (
                        <div>
                          <dt>Motiv</dt>
                          <dd>
                            <code>{finding.reason_code}</code>
                          </dd>
                        </div>
                      )}
                      <div>
                        <dt>Subiect</dt>
                        <dd>{finding.subject_identifier}</dd>
                      </div>
                      <div>
                        <dt>Metodologie</dt>
                        <dd>{finding.methodology_version}</dd>
                      </div>
                    </dl>
                    {(finding.references ?? []).length > 0 && (
                      <p className="muted">
                        Referințe: {(finding.references ?? []).join(", ")}
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
                        Îndrumare de remediere: <code>{finding.remediation_template}</code> —
                        textul complet urmează să fie publicat.
                      </p>
                    )}
                    <p className="muted">
                      Titlu în engleză: {finding.title_en}
                    </p>
                  </details>
                </li>
              );
            })}
          </ul>
        </section>
      ))}

      <p className="status" role="status" aria-live="polite">
        {message}
      </p>
    </section>
  );
}
