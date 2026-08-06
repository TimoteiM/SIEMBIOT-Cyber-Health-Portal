"use client";

import type { components } from "@siembiot/contracts/private-api-v1";
import { FormEvent, useCallback, useEffect, useState } from "react";

import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../lib/secure-client";
import { ownershipPresentation } from "../../../../lib/domain-state";

type Domain = components["schemas"]["DomainResponse"];

export default function DomainPanel({ organizationId }: { organizationId: string }) {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [domainName, setDomainName] = useState("");
  const [message, setMessage] = useState<MessageKey | null>("domains.loading");
  const { t } = useLocalization();
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    await loadSession();
    const result = await apiRequest<Domain[]>(`/api/v1/organizations/${organizationId}/domains`);
    setDomains(result);
    setMessage(result.length ? null : "domains.none");
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(apiErrorKey(error, "domains.loadFailed")),
    );
  }, [reload]);

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("domains.adding");
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/domains`, {
        method: "POST",
        body: JSON.stringify({ domain: domainName }),
      });
      setDomainName("");
      await reload();
    } catch (error) {
      setMessage(apiErrorKey(error, "domains.addFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="domains-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("domains.eyebrow")}</p>
          <h1 id="domains-title">Domenii verificate</h1>
          <p>{t("domains.intro")}</p>
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
          {t("domains.add")}
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
              <span className={`badge ${state.tone}`}>{t(state.titleKey)}</span>
              <small>{domain.canonical_name}</small>
            </li>
          );
        })}
      </ul>
      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
