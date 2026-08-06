"use client";

import { useRouter } from "next/navigation";

import { LOCALE_COOKIE, LOCALES, type Locale } from "../lib/i18n";
import { useLocalization } from "../lib/i18n/provider";

const LOCALE_LABEL_KEYS = {
  ro: "app.languageRomanian",
  en: "app.languageEnglish",
} as const;

/** A year. Long enough that a returning reader is not asked again for no reason. */
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;

export default function LanguageSwitcher() {
  const { locale, t } = useLocalization();
  const router = useRouter();

  function choose(next: Locale) {
    if (next === locale) return;
    // SameSite=Lax and no Secure flag: this is a display preference, it carries nothing
    // about the reader, and marking it Secure would silently stop it working over the
    // plain-HTTP development server.
    document.cookie =
      `${LOCALE_COOKIE}=${next}; path=/; max-age=${COOKIE_MAX_AGE_SECONDS}; samesite=lax`;
    // The server resolves the locale, so the page has to be re-fetched rather than
    // re-rendered from client state -- otherwise `lang`, the metadata and any
    // server-rendered text would keep the old language.
    router.refresh();
  }

  return (
    <div className="language-switcher" role="group" aria-label={t("app.language")}>
      {LOCALES.map((option) => (
        <button
          key={option}
          type="button"
          className="language-option"
          // aria-pressed rather than a visual highlight alone: which language is
          // active has to be announced, not only shown.
          aria-pressed={option === locale}
          onClick={() => choose(option)}
        >
          {t(LOCALE_LABEL_KEYS[option])}
        </button>
      ))}
    </div>
  );
}
