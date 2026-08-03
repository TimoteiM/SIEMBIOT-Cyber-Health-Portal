"use client";

import { useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../../../lib/secure-client";

type AuditEvent = components["schemas"]["AuditEventResponse"];

export default function AuditPanel({ organizationId }: { organizationId: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [message, setMessage] = useState("Încărcăm jurnalul…");

  useEffect(() => {
    loadSession()
      .then(() => apiRequest<AuditEvent[]>(`/api/v1/organizations/${organizationId}/audit-events`))
      .then((result) => {
        setEvents(result);
        setMessage(result.length ? "" : "Nu există evenimente de audit.");
      })
      .catch((error) =>
        setMessage(error instanceof ApiError ? error.message : "Jurnalul nu a putut fi încărcat."),
      );
  }, [organizationId]);

  return (
    <section className="panel" aria-labelledby="audit-title">
      <p className="eyebrow">Trasabilitate</p><h1 id="audit-title">Jurnal de audit</h1>
      <ol className="audit-list">{events.map((event) => (
        <li key={event.id}><strong>{event.action}</strong><span>{event.outcome}</span><time>{event.occurred_at}</time></li>
      ))}</ol>
      <p className="status" role="status" aria-live="polite">{message}</p>
    </section>
  );
}
