import Link from "next/link";
import { notFound } from "next/navigation";
import type { components } from "@siembiot/contracts/private-api-v1";

import { formatDateTime, pickLocalized, translatorFor } from "../../../lib/i18n";
import { resolveLocale } from "../../../lib/i18n/server";
import { fetchPublic } from "../../../lib/public-client";

type Profile = components["schemas"]["ObservatoryProfileResponse"];

export const dynamic = "force-dynamic";

const RESULT_CLASS: Record<string, string> = {
  pass: "success",
  warning: "neutral",
  fail: "danger",
};

/**
 * One published profile.
 *
 * Everything on this page was consented to by the organisation and permitted by the
 * methodology. What is *absent* is as deliberate: no score, no evidence, no identifier,
 * and none of the five checks the catalogue classes private -- so this page cannot be
 * assembled into something the institution did not agree to publish.
 */
export default async function ObservatoryProfilePage({
  params,
}: {
  params: Promise<{ registrableDomain: string }>;
}) {
  const { registrableDomain } = await params;
  const locale = await resolveLocale();
  const t = translatorFor(locale);

  const profile = await fetchPublic<Profile>(
    `/api/v1/public/observatory/${encodeURIComponent(registrableDomain)}`,
  );
  // The same answer whether it was never published or has been withdrawn. Telling them
  // apart would let anybody enumerate which institutions changed their mind.
  if (profile === null) notFound();

  return (
    <main className="panel observatory" id="content">
      <p className="eyebrow">
        <Link href="/observatory">{t("observatory.eyebrow")}</Link>
      </p>
      <h1>{profile.registrable_domain}</h1>

      <div className="observatory-verdict">
        {profile.band ? (
          <span className="badge neutral">{t(`band.${profile.band}` as never)}</span>
        ) : (
          <span className="badge warning">{t("band.insufficient_coverage")}</span>
        )}
        <span className="muted">
          {t("observatory.coverage", { percent: profile.coverage_percentage })}
        </span>
      </div>

      {/*
        Said before the results, not after them. A reader who takes in a list of failures
        first has already formed a judgement by the time they reach the qualification.
      */}
      <p className="hint">{t("observatory.notice")}</p>
      <p className="muted">
        {t("observatory.observed", { when: formatDateTime(locale, profile.observed_at) })}
      </p>

      <h2>{t("observatory.checksHeading")}</h2>
      <ul className="card-list observatory-checks">
        {(profile.checks ?? []).map((check) => (
          <li key={check.check_id}>
            <span className={`badge ${RESULT_CLASS[check.result] ?? "neutral"}`}>
              {t(`result.${check.result}` as never)}
            </span>
            <span>{pickLocalized(locale, check.title_ro, check.title_en)}</span>
          </li>
        ))}
      </ul>

      {/*
        The rules that produced this, named. Somebody disputing a result deserves to know
        exactly what was applied rather than being told to trust the number.
      */}
      <p className="muted">
        {t("observatory.methodology", {
          version: profile.methodology_version,
          digest: profile.policy_digest.slice(0, 12),
        })}
      </p>
      <p className="hint">{t("observatory.disputeNotice")}</p>
    </main>
  );
}
