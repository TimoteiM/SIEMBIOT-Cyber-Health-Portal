"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../../../lib/api-errors";
import type { MessageKey, Values } from "../../../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../../../lib/secure-client";

type Candidate = components["schemas"]["AssetCandidateResponse"];

const BASIS_LABELS: Record<Candidate["attribution_basis"], string> = {
  authorized_domain: "Domeniul autorizat",
  subdomain_of_authorized_domain: "Subdomeniu al domeniului autorizat",
  unrelated_name: "Nume fără legătură evidentă",
};

const STATE_LABELS: Record<Candidate["state"], string> = {
  unreviewed: "Nerevizuit",
  accepted: "Acceptat",
  rejected: "Respins",
};

function confidenceTone(candidate: Candidate): string {
  if (candidate.shared_hosting || candidate.attribution_confidence < 0.5) return "warning";
  return candidate.attribution_confidence >= 0.9 ? "success" : "neutral";
}

export default function AssetReviewPanel({
  organizationId,
  domainId,
}: {
  organizationId: string;
  domainId: string;
}) {
  const [candidates, setCandidates] = useState<Candidate[]>([]);
    /*
    A key plus its values rather than a finished sentence, so a status already on
    screen re-renders in the new language when the reader switches, instead of being
    stranded in the one it was written in.
  */
  const [message, setMessage] = useState<{ key: MessageKey; values?: Values } | null>({
    key: "assets.loading",
  });
  const { t, formatNumber } = useLocalization();
  const [busy, setBusy] = useState<string | undefined>(undefined);

  const reload = useCallback(async () => {
    await loadSession();
    setCandidates(
      await apiRequest<Candidate[]>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/asset-candidates`,
      ),
    );
    setMessage(null);
  }, [organizationId, domainId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage({ key: apiErrorKey(error, "assets.loadFailed") }),
    );
  }, [reload]);

  async function decide(candidate: Candidate, decision: "accepted" | "rejected") {
    setBusy(candidate.id);
    try {
      await apiRequest<Candidate>(
        `/api/v1/organizations/${organizationId}/asset-candidates/${candidate.id}/decision`,
        { method: "POST", body: JSON.stringify({ decision }) },
      );
      await reload();
      setMessage({
        key: decision === "accepted" ? "assets.accepted" : "assets.rejected",
        values: { name: candidate.name },
      });
    } catch (error) {
      setMessage({ key: apiErrorKey(error, "assets.decisionFailed") });
    } finally {
      setBusy(undefined);
    }
  }

  const unreviewed = candidates.filter((item) => item.state === "unreviewed");
  const decided = candidates.filter((item) => item.state !== "unreviewed");

  return (
    <section className="panel" aria-labelledby="assets-title">
      <p className="eyebrow">{t("assets.eyebrow")}</p>
      <h1 id="assets-title">{t("assets.title")}</h1>
      <p>
        Un nume descoperit public este un <strong>candidat</strong>, nu un activ confirmat.
        Nimic nu intră în perimetrul evaluat până când nu accepți explicit.
      </p>

      <h2>De revizuit ({unreviewed.length})</h2>
      {unreviewed.length === 0 ? (
        <p className="hint">{t("assets.none")}</p>
      ) : (
        <ul className="card-list">
          {unreviewed.map((candidate) => (
            <li key={candidate.id} className="candidate-card">
              <div>
                <strong>{candidate.name}</strong>
                <p className="muted">
                  {t(`attribution.${candidate.source}` as MessageKey)} ·{" "}
                  {BASIS_LABELS[candidate.attribution_basis]} · observat de{" "}
                  {candidate.observation_count} ori
                </p>
              </div>
              <span className={`badge ${confidenceTone(candidate)}`}>
                {t("assets.confidence", {
                  percent: Math.round(candidate.attribution_confidence * 100),
                })}
              </span>
              {candidate.shared_hosting && (
                <p className="muted">
                  {t("assets.sharedHosting")}
                </p>
              )}
              <div className="decision-actions">
                <button
                  type="button"
                  className="button primary"
                  disabled={busy === candidate.id}
                  onClick={() => decide(candidate, "accepted")}
                >
                  {t("assets.accept")}
                </button>
                <button
                  type="button"
                  className="button secondary"
                  disabled={busy === candidate.id}
                  onClick={() => decide(candidate, "rejected")}
                >
                  Respinge
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {decided.length > 0 && (
        <>
          <h2>Deja decise ({decided.length})</h2>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">{t("assets.decided")}</caption>
              <thead>
                <tr>
                  <th scope="col">Nume</th>
                  <th scope="col">Decizie</th>
                  <th scope="col">{t("assets.confidenceColumn")}</th>
                </tr>
              </thead>
              <tbody>
                {decided.map((candidate) => (
                  <tr key={candidate.id}>
                    <td>{candidate.name}</td>
                    <td>
                      <span
                        className={`badge ${
                          candidate.state === "accepted" ? "success" : "neutral"
                        }`}
                      >
                        {STATE_LABELS[candidate.state]}
                      </span>
                    </td>
                    <td>{Math.round(candidate.attribution_confidence * 100)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message.key, message.values) : ""}
      </p>
    </section>
  );
}
