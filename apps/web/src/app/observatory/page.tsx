import Link from "next/link";
import type { components } from "@siembiot/contracts/private-api-v1";

import { translatorFor } from "../../lib/i18n";
import { resolveLocale } from "../../lib/i18n/server";
import { fetchPublic } from "../../lib/public-client";

type Listing = components["schemas"]["ObservatoryListResponse"];

export const dynamic = "force-dynamic";

/**
 * The observatory index.
 *
 * Rendered on the server, with no client JavaScript. A public page whose whole purpose
 * is to state a published fact should not require a runtime to show it, and the people
 * most likely to read this are on whatever browser their institution provides.
 */
export default async function ObservatoryPage() {
  const locale = await resolveLocale();
  const t = translatorFor(locale);
  const listing = await fetchPublic<Listing>("/api/v1/public/observatory?limit=100");

  return (
    <main className="panel observatory" id="content">
      <p className="eyebrow">{t("observatory.eyebrow")}</p>
      <h1>{t("observatory.title")}</h1>
      <p>{t("observatory.intro")}</p>
      <p className="hint">{t("observatory.consentNotice")}</p>

      {listing === null ? (
        <p className="hint">{t("observatory.unavailable")}</p>
      ) : listing.total === 0 ? (
        /*
          The ordinary state, not an error. Nothing is published until an institution
          agrees and a named person has approved publishing at all, so an empty
          observatory is the system working rather than a page that failed to load.
        */
        <p className="hint">{t("observatory.empty")}</p>
      ) : (
        <>
          <p className="muted">{t("observatory.count", { count: listing.total })}</p>
          <ul className="card-list observatory-list">
            {(listing.profiles ?? []).map((profile) => (
              <li key={profile.registrable_domain}>
                <Link href={`/observatory/${profile.registrable_domain}`}>
                  {profile.registrable_domain}
                </Link>
                <span className={`badge ${profile.band ? "neutral" : "warning"}`}>
                  {profile.band
                    ? t(`band.${profile.band}` as never)
                    : t("band.insufficient_coverage")}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </main>
  );
}
