"use client";

import type { components } from "@siembiot/contracts/private-api-v1";
import { FormEvent, useCallback, useEffect, useState } from "react";

import { ApiError, apiRequest, loadSession } from "../../../../lib/secure-client";
import { ownershipPresentation } from "../../../../lib/domain-state";

type Domain = components["schemas"]["DomainResponse"];

export default function DomainPanel({ organizationId }: { organizationId: string }) {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [domainName, setDomainName] = useState("");
  const [message, setMessage] = useState("Încărcăm domeniile…");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    await loadSession();
    const result = await apiRequest<Domain[]>(`/api/v1/organizations/${organizationId}/domains`);
    setDomains(result);
    setMessage(result.length ? "" : "Nu există încă domenii în organizație.");
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(
        error instanceof ApiError ? error.message : "Domeniile nu au putut fi încărcate.",
      ),
    );
  }, [reload]);

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("Validăm și înregistrăm domeniul…");
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/domains`, {
        method: "POST",
        body: JSON.stringify({ domain: domainName }),
      });
      setDomainName("");
      await reload();
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Domeniul nu a putut fi adăugat.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="domains-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Suprafață autorizată</p>
          <h1 id="domains-title">Domenii verificate</h1>
          <p>Adaugă numai domenii pe care organizația are dreptul explicit să le evalueze.</p>
        </div>
        <a className="button secondary" href={`/organizations/${organizationId}/audit`}>
          Vezi auditul
        </a>
      </div>

      <form className="inline-form" onSubmit={addDomain}>
        <label htmlFor="domain-name">Nume de domeniu</label>
        <input
          id="domain-name"
          inputMode="url"
          autoComplete="off"
          required
          value={domainName}
          onChange={(event) => setDomainName(event.target.value)}
          placeholder="exemplu.ro"
        />
        <button className="button primary" disabled={busy} type="submit">
          Adaugă domeniul
        </button>
      </form>

      <ul className="card-list" aria-label="Domenii">
        {domains.map((domain) => {
          const state = ownershipPresentation(domain.ownership_state);
          return (
            <li key={domain.id}>
              <a href={`/organizations/${organizationId}/domains/${domain.id}`}>
                {domain.unicode_display}
              </a>
              <span className={`badge ${state.tone}`}>{state.title}</span>
              <small>{domain.canonical_name}</small>
            </li>
          );
        })}
      </ul>
      <p className="status" role="status" aria-live="polite">
        {message}
      </p>
    </section>
  );
}
