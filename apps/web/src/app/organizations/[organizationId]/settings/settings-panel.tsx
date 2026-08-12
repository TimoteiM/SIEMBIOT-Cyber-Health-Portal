"use client";

import { useCallback, useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type Organization = components["schemas"]["OrganizationResponse"];
type EmergencyControl = components["schemas"]["EmergencyControlResponse"];

/**
 * The organisation's own settings, and the one control with real consequence.
 *
 * An emergency control stops this platform touching an institution's systems. It existed
 * in the API and on the domain page, where somebody would only find it if they already
 * knew where to look -- which is the wrong place for a stop button. It is here as well,
 * at the level it applies to.
 *
 * Deliberately not a page of toggles. Most of what could be adjusted here should not be:
 * the methodology is versioned, the retention schedule is policy, and a per-organisation
 * override of either would make two institutions' scores incomparable.
 */
export default function SettingsPanel({ organizationId }: { organizationId: string }) {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [controls, setControls] = useState<EmergencyControl[]>([]);
  const [message, setMessage] = useState<MessageKey | null>("settings.loading");
  const [busy, setBusy] = useState(false);
  const { t, formatDateTime } = useLocalization();

  const reload = useCallback(async () => {
    await loadSession();
    const [details, active] = await Promise.all([
      apiRequest<Organization>(`/api/v1/organizations/${organizationId}`),
      apiRequest<EmergencyControl[]>(
        `/api/v1/organizations/${organizationId}/emergency-controls`,
      ),
    ]);
    setOrganization(details);
    setControls(active);
    setMessage(null);
  }, [organizationId]);

  useEffect(() => {
    reload().catch((error) => setMessage(apiErrorKey(error, "settings.loadFailed")));
  }, [reload]);

  async function stopEverything() {
    setBusy(true);
    setMessage(null);
    try {
      await apiRequest(`/api/v1/organizations/${organizationId}/emergency-controls`, {
        method: "POST",
        body: JSON.stringify({
          scope: "organization",
          reason: t("settings.stopReason"),
        }),
      });
      await reload();
      setMessage("settings.stopped2");
    } catch (error) {
      setMessage(apiErrorKey(error, "settings.stopFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function resume(controlId: string) {
    setBusy(true);
    setMessage(null);
    try {
      await apiRequest(
        `/api/v1/organizations/${organizationId}/emergency-controls/${controlId}/deactivate`,
        { method: "POST", body: JSON.stringify({ reason: t("settings.resumeReason") }) },
      );
      await reload();
      setMessage("settings.resumed");
    } catch (error) {
      setMessage(apiErrorKey(error, "settings.resumeFailed"));
    } finally {
      setBusy(false);
    }
  }

  const active = controls.filter((control) => control.active);

  return (
    <section className="panel" aria-labelledby="settings-title">
      <p className="eyebrow">{t("settings.eyebrow")}</p>
      <h1 id="settings-title">{t("settings.title")}</h1>

      {organization && (
        <dl className="facts">
          <dt>{t("settings.name")}</dt>
          <dd>{organization.name}</dd>
          <dt>{t("settings.slug")}</dt>
          <dd className="subject">{organization.slug}</dd>
          <dt>{t("settings.created")}</dt>
          <dd>{formatDateTime(organization.created_at)}</dd>
        </dl>
      )}

      <h2>{t("settings.stopHeading")}</h2>
      {/* Said before the button, not after it. Stopping is safe and resuming is the
          decision that needs thought -- an assessment halted mid-run leaves partial
          evidence, and the platform will not touch anything until somebody says so. */}
      <p className="hint">{t("settings.stopExplanation")}</p>

      {active.length === 0 ? (
        <button
          type="button"
          className="button danger"
          onClick={stopEverything}
          disabled={busy}
        >
          {t("settings.stopButton")}
        </button>
      ) : (
        <ul className="card-list">
          {active.map((control) => (
            <li key={control.id} className="finding-card">
              <div className="finding-head">
                <span className="badge danger">{t("settings.stopped")}</span>
                <h3>{control.reason}</h3>
              </div>
              <p className="muted">
                {t("settings.stoppedSince").replace(
                  "{when}",
                  formatDateTime(control.created_at),
                )}
              </p>
              <button
                type="button"
                className="button secondary"
                onClick={() => resume(control.id)}
                disabled={busy}
              >
                {t("settings.resumeButton")}
              </button>
            </li>
          ))}
        </ul>
      )}

      <h2>{t("settings.elsewhereHeading")}</h2>
      <p className="hint">{t("settings.elsewhere")}</p>

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
