"use client";

import type { components } from "@siembiot/contracts/private-api-v1";
import { useCallback, useEffect, useState } from "react";

import { ApiError, apiRequest, loadSession } from "../../../../../lib/secure-client";
import {
  challengeInstructions,
  ownershipPresentation,
} from "../../../../../lib/domain-state";

type Domain = components["schemas"]["DomainResponse"];
type Challenge = components["schemas"]["DomainChallengeCreatedResponse"];
type ChallengeMethod = components["schemas"]["DomainChallengeCreate"]["method"];
type Authorization = components["schemas"]["AssessmentAuthorizationResponse"];
type EmergencyControl = components["schemas"]["EmergencyControlResponse"];

const CONSENT_TEXT =
  "Autorizez exclusiv verificarea pasivă și verificarea proprietății pentru domeniul selectat, în intervalul indicat. Înțeleg că autorizarea poate fi revocată imediat.";

export default function DomainDetail({
  organizationId,
  domainId,
}: {
  organizationId: string;
  domainId: string;
}) {
  const [domain, setDomain] = useState<Domain>();
  const [challenge, setChallenge] = useState<Challenge>();
  const [method, setMethod] = useState<ChallengeMethod>("dns_txt");
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [controls, setControls] = useState<EmergencyControl[]>([]);
  const [consented, setConsented] = useState(false);
  const [message, setMessage] = useState("Încărcăm starea de securitate…");

  const reload = useCallback(async () => {
    await loadSession();
    const [nextDomain, nextAuthorizations, nextControls] = await Promise.all([
      apiRequest<Domain>(`/api/v1/organizations/${organizationId}/domains/${domainId}`),
      apiRequest<Authorization[]>(`/api/v1/organizations/${organizationId}/authorizations`),
      apiRequest<EmergencyControl[]>(
        `/api/v1/organizations/${organizationId}/emergency-controls`,
      ),
    ]);
    setDomain(nextDomain);
    setAuthorizations(nextAuthorizations);
    setControls(nextControls.filter((control) => control.active));
    setMessage("");
  }, [domainId, organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(error instanceof ApiError ? error.message : "Starea nu a putut fi încărcată."),
    );
  }, [reload]);

  async function createChallenge() {
    setMessage("Creăm o dovadă temporară…");
    try {
      const created = await apiRequest<Challenge>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/challenges`,
        { method: "POST", body: JSON.stringify({ method }) },
      );
      setChallenge(created);
      setMessage("Valoarea secretă este afișată o singură dată în această pagină.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Dovada nu a putut fi creată.");
    }
  }

  async function verifyChallenge() {
    if (!challenge) return;
    setMessage("Serverul verifică dovada prin canalul selectat…");
    try {
      await apiRequest(
        `/api/v1/organizations/${organizationId}/domains/${domainId}` +
          `/challenges/${challenge.id}/verify`,
        { method: "POST" },
      );
      setChallenge(undefined);
      await reload();
      setMessage("Domeniul a fost verificat de server.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Verificarea nu a reușit.");
    }
  }

  async function createAuthorization() {
    if (!consented) return;
    const validFrom = new Date();
    const validUntil = new Date(validFrom.getTime() + 24 * 60 * 60 * 1000);
    setMessage("Înregistrăm consimțământul și domeniul exact…");
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations`, {
        method: "POST",
        body: JSON.stringify({
          domain_ids: [domainId],
          operation_classes: ["dns_verification", "https_verification"],
          policy_version: "scope-v1",
          consent_version: "ro-v1",
          consent_text: CONSENT_TEXT,
          valid_from: validFrom.toISOString(),
          valid_until: validUntil.toISOString(),
        }),
      });
      setConsented(false);
      await reload();
      setMessage("Schița autorizării a fost creată. Activarea rămâne un pas explicit.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Autorizarea nu a putut fi creată.");
    }
  }

  async function activateAuthorization(id: string) {
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations/${id}/accept`, {
        method: "POST",
      });
      await reload();
      setMessage("Autorizarea semnată de server este activă.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Autorizarea nu a putut fi activată.");
    }
  }

  async function revokeAuthorization(id: string) {
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations/${id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason: "Revocare explicită solicitată din portal" }),
      });
      await reload();
      setMessage("Autorizarea a fost revocată imediat.");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Revocarea nu a putut fi aplicată.");
    }
  }

  if (!domain) {
    return (
      <section className="panel narrow" aria-busy="true">
        <p className="status" role="status" aria-live="polite">
          {message}
        </p>
      </section>
    );
  }

  const state = ownershipPresentation(domain.ownership_state);
  return (
    <section className="panel" aria-labelledby="domain-title">
      {controls.length > 0 && (
        <div className="security-banner" role="alert">
          Operațiunile de rețea sunt suspendate printr-un control de urgență.
        </div>
      )}
      <p className="eyebrow">Domeniu și autorizare</p>
      <h1 id="domain-title">{domain.unicode_display}</h1>
      <p className={`state-card ${state.tone}`}>
        <strong>{state.title}</strong> — {state.detail}
      </p>
      <p className="hint">Ținta canonică exactă: {domain.canonical_name}</p>

      <div className="workflow-grid">
        <section aria-labelledby="proof-title">
          <h2 id="proof-title">1. Dovedește controlul</h2>
          <label htmlFor="challenge-method">Metodă de verificare</label>
          <select
            id="challenge-method"
            value={method}
            onChange={(event) => setMethod(event.target.value as ChallengeMethod)}
          >
            <option value="dns_txt">Înregistrare DNS TXT</option>
            <option value="https_file">Fișier HTTPS fix</option>
          </select>
          <button className="button secondary" type="button" onClick={createChallenge}>
            Creează dovada
          </button>
          {challenge && (
            <div className="secret-panel">
              <p>{challengeInstructions(challenge.method, challenge.verification_location)}</p>
              <label htmlFor="verification-token">Valoare afișată o singură dată</label>
              <output id="verification-token">{challenge.verification_token}</output>
              <p>
                Expiră la {new Date(challenge.expires_at).toLocaleString("ro-RO")}; mai sunt{" "}
                {challenge.attempts_remaining} încercări.
              </p>
              <button className="button primary" type="button" onClick={verifyChallenge}>
                Verifică acum
              </button>
            </div>
          )}
        </section>

        <section aria-labelledby="authorization-title">
          <h2 id="authorization-title">2. Autorizează explicit</h2>
          <p>{CONSENT_TEXT}</p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={consented}
              onChange={(event) => setConsented(event.target.checked)}
            />
            Confirm că am dreptul să autorizez domeniul exact și intervalul de 24 de ore.
          </label>
          <button
            className="button secondary"
            type="button"
            disabled={!consented || domain.ownership_state !== "verified"}
            onClick={createAuthorization}
          >
            Creează schița autorizării
          </button>
          <ul className="authorization-list">
            {authorizations.map((authorization) => (
              <li key={authorization.id}>
                <strong>{authorization.state}</strong> — expiră la{" "}
                {new Date(authorization.valid_until).toLocaleString("ro-RO")}
                {authorization.state === "draft" && (
                  <button
                    className="button primary"
                    type="button"
                    onClick={() => activateAuthorization(authorization.id)}
                  >
                    Acceptă și semnează pe server
                  </button>
                )}
                {authorization.state === "active" && (
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => revokeAuthorization(authorization.id)}
                  >
                    Revocă autorizarea
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>
      </div>
      <p className="status" role="status" aria-live="polite">
        {message}
      </p>
    </section>
  );
}
