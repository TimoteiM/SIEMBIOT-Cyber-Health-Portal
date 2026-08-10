"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../lib/i18n/provider";
import { apiErrorKey } from "../../lib/api-errors";
import type { MessageKey } from "../../lib/i18n";
import { ApiError, apiRequest, loadSession } from "../../lib/secure-client";

type Organization = components["schemas"]["OrganizationResponse"];

/**
 * Mirrors the server's slug rule exactly: it must start and end with a letter or
 * digit, so a trailing hyphen is invalid. The previous pattern allowed one, which
 * meant "tarom-" passed in the browser and came back a 422 from the API — the reader
 * being told nothing was wrong right up until it was.
 *
 * The hyphen is escaped because browsers now compile the `pattern` attribute with the
 * RegExp `v` flag, under which a bare `-` at the end of a character class is a syntax
 * error rather than a literal. An invalid pattern does not fail safe: the browser
 * throws while parsing it and the field ends up with no validation at all.
 */
const SLUG_PATTERN = "[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?";

/**
 * The way in.
 *
 * This page used to be the create-an-organization form and nothing else, so somebody who
 * already belonged to two organizations was still asked to make a third — there was no
 * screen anywhere that listed the ones they were in, and the only way to reach a
 * workspace was to know its identifier and type the URL. Creating one is the rarer
 * action, so it is now the secondary one.
 */
export default function OnboardingPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState<MessageKey | null>("onboarding.checkingIdentity");
  const { t, formatDateTime } = useLocalization();

  const load = useCallback(async () => {
    await loadSession();
    setOrganizations(await apiRequest<Organization[]>("/api/v1/organizations"));
    setReady(true);
    setMessage(null);
  }, []);

  useEffect(() => {
    load().catch((error: unknown) => {
      setReady(false);
      setMessage(
        error instanceof ApiError && error.status === 401
          ? "error.identityMissing"
          : apiErrorKey(error, "onboarding.loadFailed"),
      );
    });
  }, [load]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setMessage("onboarding.creating");
    try {
      const organization = await apiRequest<Organization>("/api/v1/organizations", {
        method: "POST",
        body: JSON.stringify({ name: data.get("name"), slug: data.get("slug") }),
      });
      router.push(`/organizations/${organization.id}/domains`);
    } catch (error) {
      setMessage(apiErrorKey(error, "error.generic"));
    }
  }

  const showForm = creating || (ready && organizations.length === 0);

  return (
    <section className="panel narrow" aria-labelledby="onboarding-title">
      <p className="eyebrow">
        {organizations.length > 0 ? t("onboarding.chooseEyebrow") : t("onboarding.eyebrow")}
      </p>
      <h1 id="onboarding-title">
        {organizations.length > 0 ? t("onboarding.chooseTitle") : t("onboarding.title")}
      </h1>

      {organizations.length > 0 && (
        <>
          <p>{t("onboarding.chooseIntro")}</p>
          <ul className="card-list organization-list">
            {organizations.map((organization) => (
              <li key={organization.id}>
                {/*
                  Straight to the domains screen rather than to the team page. Somebody
                  arriving here wants to see what the platform knows about them, and
                  membership administration is not that.
                */}
                <a href={`/organizations/${organization.id}/domains`}>{organization.name}</a>
                <small className="muted">{organization.slug}</small>
                {/*
                  Support access is labelled and a membership is not. Somebody supporting
                  a customer should be able to see that this is somebody else's data;
                  rendering the two identically is what would make that invisible.
                */}
                {organization.role === "platform_support" ? (
                  <span className="badge warning">{t("onboarding.viaSupportAccess")}</span>
                ) : (
                  <small className="muted">{formatDateTime(organization.created_at)}</small>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      {showForm ? (
        <form onSubmit={submit}>
          <label htmlFor="name">{t("onboarding.name")}</label>
          <input id="name" name="name" required maxLength={200} autoComplete="organization" />
          <label htmlFor="slug">{t("onboarding.slug")}</label>
          <input
            id="slug"
            name="slug"
            required
            pattern={SLUG_PATTERN}
            title={t("onboarding.slugHint")}
          />
          <button className="button primary" type="submit" disabled={!ready}>
            {t("onboarding.submit")}
          </button>
        </form>
      ) : (
        ready && (
          <button className="button secondary" type="button" onClick={() => setCreating(true)}>
            {t("onboarding.createAnother")}
          </button>
        )
      )}

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
