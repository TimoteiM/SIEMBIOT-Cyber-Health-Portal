"use client";

import { useEffect, useState } from "react";
import type { components } from "@siembiot/contracts/private-api-v1";

import { ApiError, apiRequest, loadSession } from "../../../../lib/secure-client";

type Membership = components["schemas"]["MembershipResponse"];

export default function TeamPanel({ organizationId }: { organizationId: string }) {
  const [members, setMembers] = useState<Membership[]>([]);
  const [message, setMessage] = useState("Încărcăm echipa…");

  useEffect(() => {
    loadSession()
      .then(() => apiRequest<Membership[]>(`/api/v1/organizations/${organizationId}/memberships`))
      .then((result) => {
        setMembers(result);
        setMessage(result.length ? "" : "Nu există membri de afișat.");
      })
      .catch((error) =>
        setMessage(error instanceof ApiError ? error.message : "Echipa nu a putut fi încărcată."),
      );
  }, [organizationId]);

  return (
    <section className="panel" aria-labelledby="team-title">
      <div className="section-heading">
        <div><p className="eyebrow">Control acces</p><h1 id="team-title">Echipă și roluri</h1></div>
        <a className="button secondary" href={`/organizations/${organizationId}/audit`}>Vezi auditul</a>
      </div>
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Membrii organizației și rolurile active</caption>
          <thead><tr><th scope="col">Utilizator</th><th scope="col">Rol</th><th scope="col">Stare</th></tr></thead>
          <tbody>{members.map((member) => (
            <tr key={member.id}><td>{member.user_id}</td><td>{member.role}</td><td>{member.status}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <p className="status" role="status" aria-live="polite">{message}</p>
    </section>
  );
}
