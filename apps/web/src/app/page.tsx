import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import {
  accountBySubject,
  DEV_IDENTITY_COOKIE,
  developmentSignInEnabled,
  SIGNED_IN_HOME,
} from "../lib/dev-accounts";
import { translate } from "../lib/i18n";
import { resolveLocale } from "../lib/i18n/server";

/**
 * The first page, which in development is the sign-in page.
 *
 * Opening the application with no identity chosen and being shown a hero with a button
 * is a step that exists only to be clicked through. So locally, the root redirects
 * straight to sign-in -- and straight past it to the application when an identity has
 * already been chosen, because bouncing a signed-in person back to a sign-in page reads
 * as the session having been lost.
 *
 * **Only in development.** A real deployment terminates identity at a gateway upstream
 * and has no sign-in page to redirect to; sending people to one that says on its face
 * that it does not authenticate would be worse than the landing page. So production
 * keeps the landing page, and the redirect is gated on the same flag that gates the
 * sign-in page itself, rather than on a second condition that could drift from it.
 */
export default async function LandingPage() {
  if (developmentSignInEnabled()) {
    const chosen = (await cookies()).get(DEV_IDENTITY_COOKIE)?.value;
    // Resolved against the accounts that exist rather than merely being present: a
    // cookie left over from a renamed account would otherwise send somebody into the
    // application with an identity the API will not accept, and the failure would
    // surface several pages later as an unexplained 401.
    redirect(chosen && accountBySubject(chosen) ? SIGNED_IN_HOME : "/sign-in");
  }

  const locale = await resolveLocale();
  return (
    <section className="hero" aria-labelledby="landing-title">
      <p className="eyebrow">{translate(locale, "landing.eyebrow")}</p>
      <h1 id="landing-title">{translate(locale, "landing.title")}</h1>
      <p>{translate(locale, "landing.intro")}</p>
      <a className="button primary" href="/onboarding">
        {translate(locale, "landing.enter")}
      </a>
      <p className="hint">{translate(locale, "landing.note")}</p>
    </section>
  );
}
