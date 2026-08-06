"use client";

import { useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { useLocalization } from "../../../../lib/i18n/provider";
import { apiErrorKey } from "../../../../lib/api-errors";
import type { MessageKey } from "../../../../lib/i18n";
import { apiRequest, loadSession } from "../../../../lib/secure-client";

type Membership = components["schemas"]["MembershipResponse"];

export default function TeamPanel({ organizationId }: { organizationId: string }) {
  const [members, setMembers] = useState<Membership[]>([]);
  const [message, setMessage] = useState<MessageKey | null>("team.loading");
  const { t } = useLocalization();

  useEffect(() => {
    loadSession()
      .then(() => apiRequest<Membership[]>(`/api/v1/organizations/${organizationId}/memberships`))
      .then((result) => {
        setMembers(result);
        setMessage(result.length ? null : "team.none");
      })
      .catch((error) =>
        setMessage(apiErrorKey(error, "team.loadFailed")),
      );
  }, [organizationId]);

  return (
    <section className="panel" aria-labelledby="team-title">
      <div className="section-heading">
        <div><p className="eyebrow">{t("team.eyebrow")}</p><h1 id="team-title">{t("team.title")}</h1></div>
        <a className="button secondary" href={`/organizations/${organizationId}/audit`}>Vezi auditul</a>
      </div>
      <div className="table-wrap">
        <table>
          <caption className="sr-only">{t("team.caption")}</caption>
          <thead><tr><th scope="col">Utilizator</th><th scope="col">Rol</th><th scope="col">Stare</th></tr></thead>
          <tbody>{members.map((member) => (
            <tr key={member.id}><td>{member.user_id}</td><td>{member.role}</td><td>{member.status}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <p className="status" role="status" aria-live="polite">{message ? t(message) : ""}</p>
    </section>
  );
}
