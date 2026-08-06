import { translate } from "../lib/i18n";
import { resolveLocale } from "../lib/i18n/server";

export default async function LandingPage() {
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
