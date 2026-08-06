"use client";

import { FormEvent, useEffect, useState } from "react";
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

export default function OnboardingPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState<MessageKey | null>("onboarding.checkingIdentity");
  const { t } = useLocalization();

  useEffect(() => {
    loadSession()
      .then(() => {
        setReady(true);
        setMessage(null);
      })
      .catch((error: unknown) => {
        // Authentication happens upstream, so there is no login page to send anyone
        // to. Say what is actually true: the identity did not arrive.
        setMessage(
          error instanceof ApiError && error.status === 401
            ? "error.identityMissing"
            : "onboarding.loadFailed",
        );
      });
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setMessage("onboarding.creating");
    try {
      const organization = await apiRequest<Organization>("/api/v1/organizations", {
        method: "POST",
        body: JSON.stringify({ name: data.get("name"), slug: data.get("slug") }),
      });
      router.push(`/organizations/${organization.id}/team`);
    } catch (error) {
      setMessage(apiErrorKey(error, "error.generic"));
    }
  }

  return (
    <section className="panel narrow" aria-labelledby="onboarding-title">
      <p className="eyebrow">{t("onboarding.eyebrow")}</p>
      <h1 id="onboarding-title">{t("onboarding.title")}</h1>
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
        <button className="button primary" type="submit" disabled={!ready}>{t("onboarding.submit")}</button>
      </form>
      <p className="status" role="status" aria-live="polite">{message ? t(message) : ""}</p>
    </section>
  );
}
