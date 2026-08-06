"use client";

import { useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type AuditEvent = components["schemas"]["AuditEventResponse"];

export default function AuditPanel({ organizationId }: { organizationId: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [message, setMessage] = useState<MessageKey | null>("audit.loading");
  const { t, formatDateTime } = useLocalization();

  useEffect(() => {
    loadSession()
      .then(() => apiRequest<AuditEvent[]>(`/api/v1/organizations/${organizationId}/audit-events`))
      .then((result) => {
        setEvents(result);
        setMessage(result.length ? null : "audit.none");
      })
      .catch((error) =>
        setMessage(apiErrorKey(error, "audit.loadFailed")),
      );
  }, [organizationId]);

  return (
    <section className="panel" aria-labelledby="audit-title">
      <p className="eyebrow">Trasabilitate</p><h1 id="audit-title">Jurnal de audit</h1>
      <ol className="audit-list">{events.map((event) => (
        <li key={event.id}><strong>{event.action}</strong><span>{event.outcome}</span><time>{event.occurred_at}</time></li>
      ))}</ol>
      <p className="status" role="status" aria-live="polite">{message ? t(message) : ""}</p>
    </section>
  );
}
