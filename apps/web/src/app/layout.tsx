import type { Metadata } from "next";
import type { ReactNode } from "react";

import { LANGUAGE_TAGS, translate } from "../lib/i18n";
import { LocalizationProvider } from "../lib/i18n/provider";
import { resolveLocale } from "../lib/i18n/server";
import AppShell from "./shell";
import "./styles.css";

/**
 * Metadata is resolved per request so the browser tab and any link preview arrive in
 * the reader's language, not only the page body.
 */
export async function generateMetadata(): Promise<Metadata> {
  const locale = await resolveLocale();
  return {
    title: translate(locale, "app.title"),
    description: translate(locale, "app.description"),
  };
}

export default async function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  const locale = await resolveLocale();
  return (
    // `lang` is what tells a screen reader which voice to use. Hardcoded to Romanian it
    // would read English text with Romanian pronunciation, which is harder to follow
    // than either language on its own.
    <html lang={LANGUAGE_TAGS[locale]}>
      <body>
        <LocalizationProvider locale={locale}>
          <a className="skip-link" href="#main">
            {translate(locale, "app.skipToContent")}
          </a>
          <AppShell>{children}</AppShell>
        </LocalizationProvider>
      </body>
    </html>
  );
}
