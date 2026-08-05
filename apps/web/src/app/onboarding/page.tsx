"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../lib/secure-client";

type Organization = components["schemas"]["OrganizationResponse"];

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
        <input id="slug" name="slug" required pattern="[a-z0-9][a-z0-9-]{0,62}" />
        <button className="button primary" type="submit" disabled={!ready}>Continuă</button>
      </form>
      <p className="status" role="status" aria-live="polite">{message}</p>
    </section>
  );
}
