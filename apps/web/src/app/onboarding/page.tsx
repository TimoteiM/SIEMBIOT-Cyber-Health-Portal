"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { components } from "@siembiot/contracts/private-api-v1";

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
  const [message, setMessage] = useState("Verificăm identitatea…");

  useEffect(() => {
    loadSession()
      .then(() => {
        setReady(true);
        setMessage("");
      })
      .catch((error: unknown) => {
        // Authentication happens upstream, so there is no login page to send anyone
        // to. Say what is actually true: the identity did not arrive.
        setMessage(
          error instanceof ApiError && error.status === 401
            ? "Identitatea nu a fost primită de la platforma de identitate. " +
                "Reîncarcă pagina sau contactează administratorul."
            : "Starea nu a putut fi încărcată.",
        );
      });
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setMessage("Creăm organizația…");
    try {
      const organization = await apiRequest<Organization>("/api/v1/organizations", {
        method: "POST",
        body: JSON.stringify({ name: data.get("name"), slug: data.get("slug") }),
      });
      router.push(`/organizations/${organization.id}/team`);
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Cererea nu a putut fi finalizată.");
    }
  }

  return (
    <section className="panel narrow" aria-labelledby="onboarding-title">
      <p className="eyebrow">Configurare inițială</p>
      <h1 id="onboarding-title">Creează spațiul organizației</h1>
      <form onSubmit={submit}>
        <label htmlFor="name">Numele organizației</label>
        <input id="name" name="name" required maxLength={200} autoComplete="organization" />
        <label htmlFor="slug">Identificator scurt</label>
        <input
          id="slug"
          name="slug"
          required
          pattern={SLUG_PATTERN}
          title="Litere mici, cifre și cratime. Trebuie să înceapă și să se termine cu o literă sau o cifră."
        />
        <button className="button primary" type="submit" disabled={!ready}>Continuă</button>
      </form>
      <p className="status" role="status" aria-live="polite">{message}</p>
    </section>
  );
}
