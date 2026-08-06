"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../../../../../lib/secure-client";

type Candidate = components["schemas"]["AssetCandidateResponse"];

const BASIS_LABELS: Record<Candidate["attribution_basis"], string> = {
  authorized_domain: "Domeniul autorizat",
  subdomain_of_authorized_domain: "Subdomeniu al domeniului autorizat",
  unrelated_name: "Nume fără legătură evidentă",
};

const SOURCE_LABELS: Record<Candidate["source"], string> = {
  certificate_transparency: "Certificate Transparency",
  dns: "DNS",
  user_declared: "Declarat de organizație",
  passive_intelligence: "Sursă pasivă",
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
  const [message, setMessage] = useState("Încărcăm candidații…");
  const [busy, setBusy] = useState<string | undefined>(undefined);

  const reload = useCallback(async () => {
    await loadSession();
    setCandidates(
      await apiRequest<Candidate[]>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/asset-candidates`,
      ),
    );
    setMessage("");
  }, [organizationId, domainId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(error instanceof ApiError ? error.message : "Starea nu a putut fi încărcată."),
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
      setMessage(
        decision === "accepted"
          ? `${candidate.name} a fost inclus în perimetrul evaluat.`
          : `${candidate.name} a fost exclus din perimetrul evaluat.`,
      );
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Decizia nu a putut fi salvată.");
    } finally {
      setBusy(undefined);
    }
  }

  const unreviewed = candidates.filter((item) => item.state === "unreviewed");
  const decided = candidates.filter((item) => item.state !== "unreviewed");

  return (
    <section className="panel" aria-labelledby="assets-title">
      <p className="eyebrow">Atribuirea activelor</p>
      <h1 id="assets-title">Candidați descoperiți</h1>
      <p>
        Un nume descoperit public este un <strong>candidat</strong>, nu un activ confirmat.
        Nimic nu intră în perimetrul evaluat până când nu accepți explicit.
      </p>

      <h2>De revizuit ({unreviewed.length})</h2>
      {unreviewed.length === 0 ? (
        <p className="hint">Niciun candidat în așteptare.</p>
      ) : (
        <ul className="card-list">
          {unreviewed.map((candidate) => (
            <li key={candidate.id} className="candidate-card">
              <div>
                <strong>{candidate.name}</strong>
                <p className="muted">
                  {SOURCE_LABELS[candidate.source]} ·{" "}
                  {BASIS_LABELS[candidate.attribution_basis]} · observat de{" "}
                  {candidate.observation_count} ori
                </p>
              </div>
              <span className={`badge ${confidenceTone(candidate)}`}>
                încredere {Math.round(candidate.attribution_confidence * 100)}%
              </span>
              {candidate.shared_hosting && (
                <p className="muted">
                  Găzduire partajată: certificatul unui alt client nu spune nimic despre
                  proprietatea acestui nume.
                </p>
              )}
              <div className="decision-actions">
                <button
                  type="button"
                  className="button primary"
                  disabled={busy === candidate.id}
                  onClick={() => decide(candidate, "accepted")}
                >
                  Acceptă
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
              <caption className="sr-only">Candidați deja acceptați sau respinși</caption>
              <thead>
                <tr>
                  <th scope="col">Nume</th>
                  <th scope="col">Decizie</th>
                  <th scope="col">Încredere</th>
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
        {message}
      </p>
    </section>
  );
}
