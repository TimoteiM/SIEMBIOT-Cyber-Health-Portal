"use client";

import { useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type Provider = components["schemas"]["ProviderResponse"];
type Providers = components["schemas"]["ProvidersResponse"];

/**
 * Who else sees anything as a result of an assessment.
 *
 * An institution enrolling a domain is entitled to that answer, and most of it is
 * reassuring -- the collectors are keyless and read public registries. But "most" is not
 * something a public body should have to take on trust, so the list is published rather
 * than described.
 *
 * Read from the adapter descriptors the collectors actually run under, so this page
 * cannot name a provider the platform does not use, or omit one it does.
 */
export default function ProvidersPanel() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [message, setMessage] = useState<MessageKey | null>("providers.loading");
  const { t } = useLocalization();

  useEffect(() => {
    loadSession()
      .then(() => apiRequest<Providers>("/api/v1/providers"))
      .then((result) => {
        setProviders(result.providers);
        setMessage(result.providers.length ? null : "providers.none");
      })
      .catch((error) => setMessage(apiErrorKey(error, "providers.loadFailed")));
  }, []);

  const keyless = providers.filter((provider) => provider.required_secrets.length === 0).length;

  return (
    <section className="panel" aria-labelledby="providers-title">
      <p className="eyebrow">{t("providers.eyebrow")}</p>
      <h1 id="providers-title">{t("providers.title")}</h1>
      <p className="hint">{t("providers.intro")}</p>

      {providers.length > 0 && (
        <p className="note">
          {t("providers.keylessSummary")
            .replace("{keyless}", String(keyless))
            .replace("{total}", String(providers.length))}
        </p>
      )}

      <ul className="card-list">
        {providers.map((provider) => (
          <li key={provider.adapter_id} className="finding-card">
            <div className="finding-head">
              <h3>{provider.title}</h3>
              <span className="badge neutral">{provider.group}</span>
              {/* Stated per provider rather than only in the summary: an operator
                  scanning one row should not have to hold the total in their head. */}
              <span className="badge neutral">
                {provider.required_secrets.length === 0
                  ? t("providers.keyless")
                  : t("providers.needsCredential")}
              </span>
            </div>

            <dl className="finding-meta">
              <div>
                <dt>{t("providers.reads")}</dt>
                <dd>{provider.capabilities.join(", ")}</dd>
              </div>
              <div>
                <dt>{t("providers.classification")}</dt>
                <dd>{provider.data_classification}</dd>
              </div>
              <div>
                <dt>{t("providers.cost")}</dt>
                <dd>{provider.cost_unit}</dd>
              </div>
              <div>
                <dt>{t("providers.testable")}</dt>
                <dd>
                  {provider.supports_fixtures ? t("providers.yes") : t("providers.no")}
                </dd>
              </div>
            </dl>

            <p className="muted">{provider.terms_notes}</p>
            {provider.terms_url && (
              <p>
                <a href={provider.terms_url} rel="noreferrer noopener" target="_blank">
                  {t("providers.terms")}
                </a>
              </p>
            )}
          </li>
        ))}
      </ul>

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
