"use client";

import type { components } from "@siembiot/contracts/private-api-v1";
import { useCallback, useEffect, useState } from "react";

import { useLocalization } from "../../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../../lib/api-errors";
import type { MessageKey } from "../../../../../lib/i18n";
import { consentFor } from "../../../../../lib/consent";
import { ApiError, apiRequest, loadSession } from "../../../../../lib/secure-client";
import {
  challengeInstructionKey,
  ownershipPresentation,
} from "../../../../../lib/domain-state";

type Domain = components["schemas"]["DomainResponse"];
type Challenge = components["schemas"]["DomainChallengeCreatedResponse"];
type ChallengeMethod = components["schemas"]["DomainChallengeCreate"]["method"];
type Authorization = components["schemas"]["AssessmentAuthorizationResponse"];
type EmergencyControl = components["schemas"]["EmergencyControlResponse"];

type Consent = components["schemas"]["ConsentResponse"];

/**
 * Publishing to the public observatory.
 *
 * Two things this control has to keep visibly apart, because they are separate facts and
 * an interface that merges them will eventually tell somebody they are published when
 * they are not: agreeing to publication, and being published. Consent is permission, and
 * nothing appears until an assessment has run and the platform's own publication review
 * has been recorded.
 *
 * Withdrawal is a plain button with no confirmation step. Everywhere else in this product
 * a destructive action deserves friction; here the destructive direction is *staying*
 * published, and an institution that wants out should not have to argue with a dialog.
 */
function PublicationSection({
  organizationId,
  domainId,
  verified,
  onMessage,
}: {
  organizationId: string;
  domainId: string;
  verified: boolean;
  onMessage: (key: MessageKey) => void;
}) {
  const { t, formatDateTime } = useLocalization();
  const [state, setState] = useState<Consent>();
  const [busy, setBusy] = useState(false);
  const path = `/api/v1/organizations/${organizationId}/domains/${domainId}/publication`;

  useEffect(() => {
    apiRequest<Consent>(path)
      .then(setState)
      .catch(() => undefined);
  }, [path]);

  async function change(method: "PUT" | "DELETE") {
    setBusy(true);
    try {
      setState(
        await apiRequest<Consent>(path, {
          method,
          body: method === "DELETE" ? JSON.stringify({}) : undefined,
        }),
      );
      onMessage(method === "PUT" ? "publication.granted" : "publication.withdrawn");
    } catch (error) {
      onMessage(apiErrorKey(error, "publication.changeFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="publication-title">
      <h2 id="publication-title">{t("publication.heading")}</h2>
      <p>{t("publication.explainer")}</p>

      {!verified && <p className="hint">{t("publication.needsVerification")}</p>}

      {state?.consented ? (
        <>
          <p className="muted">
            {state.published_at
              ? t("publication.published", { when: formatDateTime(state.published_at) })
              : t("publication.consentedNotPublished")}
          </p>
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() => change("DELETE")}
          >
            {t("publication.withdraw")}
          </button>
        </>
      ) : (
        <button
          className="button secondary"
          type="button"
          disabled={busy || !verified}
          onClick={() => change("PUT")}
        >
          {t("publication.grant")}
        </button>
      )}
    </section>
  );
}

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
  const [message, setMessage] = useState<MessageKey | null>("domainDetail.loading");
  const { t, locale, formatDateTime } = useLocalization();

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
    setMessage(null);
  }, [domainId, organizationId]);

  useEffect(() => {
    reload().catch((error: unknown) =>
      setMessage(apiErrorKey(error, "domainDetail.loadFailed")),
    );
  }, [reload]);

  async function createChallenge() {
    setMessage("domainDetail.creatingChallenge");
    try {
      const created = await apiRequest<Challenge>(
        `/api/v1/organizations/${organizationId}/domains/${domainId}/challenges`,
        { method: "POST", body: JSON.stringify({ method }) },
      );
      setChallenge(created);
      setMessage("domainDetail.secretShownOnce");
    } catch (error) {
      setMessage(apiErrorKey(error, "domainDetail.challengeFailed"));
    }
  }

  async function verifyChallenge() {
    if (!challenge) return;
    setMessage("domainDetail.verifying");
    try {
      await apiRequest(
        `/api/v1/organizations/${organizationId}/domains/${domainId}` +
          `/challenges/${challenge.id}/verify`,
        { method: "POST" },
      );
      setChallenge(undefined);
      await reload();
      setMessage("domainDetail.verified");
    } catch (error) {
      setMessage(apiErrorKey(error, "domainDetail.verifyFailed"));
    }
  }

  async function createAuthorization() {
    if (!consented) return;
    const validFrom = new Date();
    const validUntil = new Date(validFrom.getTime() + 24 * 60 * 60 * 1000);
    setMessage("domainDetail.recordingConsent");
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations`, {
        method: "POST",
        body: JSON.stringify({
          domain_ids: [domainId],
          operation_classes: ["dns_verification", "https_verification"],
          policy_version: "scope-v1",
          consent_version: consentFor(locale).version,
          consent_text: consentFor(locale).text,
          valid_from: validFrom.toISOString(),
          valid_until: validUntil.toISOString(),
        }),
      });
      setConsented(false);
      await reload();
      setMessage("domainDetail.authorizationDrafted");
    } catch (error) {
      setMessage(apiErrorKey(error, "domainDetail.authorizationFailed"));
    }
  }

  async function activateAuthorization(id: string) {
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations/${id}/accept`, {
        method: "POST",
      });
      await reload();
      setMessage("domainDetail.authorizationActive");
    } catch (error) {
      setMessage(apiErrorKey(error, "domainDetail.activationFailed"));
    }
  }

  async function revokeAuthorization(id: string) {
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/authorizations/${id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason: t("domainDetail.revokeReason") }),
      });
      await reload();
      setMessage("domainDetail.revoked");
    } catch (error) {
      setMessage(apiErrorKey(error, "domainDetail.revokeFailed"));
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
          {t("domainDetail.emergencyActive")}
        </div>
      )}
      <p className="eyebrow">{t("domainDetail.eyebrow")}</p>
      <h1 id="domain-title">{domain.unicode_display}</h1>
      <p className={`state-card ${state.tone}`}>
        <strong>{t(state.titleKey)}</strong> — {t(state.detailKey)}
      </p>
      <p className="hint">{t("domainDetail.canonicalTarget", { host: domain.canonical_name })}</p>

      <div className="workflow-grid">
        <section aria-labelledby="proof-title">
          <h2 id="proof-title">{t("domainDetail.proofHeading")}</h2>
          <label htmlFor="challenge-method">{t("domainDetail.method")}</label>
          <select
            id="challenge-method"
            value={method}
            onChange={(event) => setMethod(event.target.value as ChallengeMethod)}
          >
            <option value="dns_txt">{t("domainDetail.methodDns")}</option>
            <option value="https_file">{t("domainDetail.methodHttps")}</option>
          </select>
          <button className="button secondary" type="button" onClick={createChallenge}>
            {t("domainDetail.createChallenge")}
          </button>
          {challenge && (
            <div className="secret-panel">
              <p>
                {t(challengeInstructionKey(challenge.method), {
                  location: challenge.verification_location,
                })}
              </p>
              <label htmlFor="verification-token">{t("domainDetail.tokenLabel")}</label>
              <output id="verification-token">{challenge.verification_token}</output>
              <p>
                {t("domainDetail.expiresAttempts", {
                  expires: formatDateTime(challenge.expires_at),
                  attempts: challenge.attempts_remaining,
                })}
              </p>
              <button className="button primary" type="button" onClick={verifyChallenge}>
                {t("domainDetail.verifyNow")}
              </button>
            </div>
          )}
        </section>

        <section aria-labelledby="authorization-title">
          <h2 id="authorization-title">{t("domainDetail.authorizeHeading")}</h2>
          <p>{consentFor(locale).text}</p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={consented}
              onChange={(event) => setConsented(event.target.checked)}
            />
            {t("domainDetail.consentConfirm")}
          </label>
          <button
            className="button secondary"
            type="button"
            disabled={!consented || domain.ownership_state !== "verified"}
            onClick={createAuthorization}
          >
            {t("domainDetail.createDraft")}
          </button>
          <ul className="authorization-list">
            {authorizations.map((authorization) => (
              <li key={authorization.id}>
                <strong>{authorization.state}</strong> —{" "}
                {t("domainDetail.expiresAt", {
                  expires: formatDateTime(authorization.valid_until),
                })}
                {authorization.state === "draft" && (
                  <button
                    className="button primary"
                    type="button"
                    onClick={() => activateAuthorization(authorization.id)}
                  >
                    {t("domainDetail.signOnServer")}
                  </button>
                )}
                {authorization.state === "active" && (
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => revokeAuthorization(authorization.id)}
                  >
                    {t("domainDetail.revoke")}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>

        <PublicationSection
          organizationId={organizationId}
          domainId={domainId}
          verified={domain.ownership_state === "verified"}
          onMessage={setMessage}
        />
      </div>
      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
