import { cookies, headers } from "next/headers";

import { DEFAULT_LOCALE, isLocale, LOCALE_COOKIE, localeFromAcceptLanguage, type Locale } from "./index";

/**
 * The locale for this request, resolved on the server so the first paint is already in
 * the right language.
 *
 * Order: an explicit choice, then the browser's preference, then Romanian. Resolving
 * on the client instead would render Romanian and then swap it -- a visible flash that
 * tells an English reader the product was not really built for them.
 */
export async function resolveLocale(): Promise<Locale> {
  const store = await cookies();
  const chosen = store.get(LOCALE_COOKIE)?.value;
  if (isLocale(chosen)) return chosen;

  const header = (await headers()).get("accept-language");
  return localeFromAcceptLanguage(header) ?? DEFAULT_LOCALE;
}
