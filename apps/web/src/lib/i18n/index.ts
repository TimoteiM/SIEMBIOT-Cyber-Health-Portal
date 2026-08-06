/**
 * Translation lookup and locale-aware formatting.
 *
 * Written here rather than taken from a library because what the product needs is a
 * dictionary, an interpolator and two `Intl` calls. A routing-opinionated i18n package
 * would also want to own the URL structure, which already carries organization and
 * domain identifiers and has middleware in front of it.
 */

import {
  CATALOGUES,
  DEFAULT_LOCALE,
  type Locale,
  type MessageKey,
  type Messages,
} from "./messages";

export {
  CATALOGUES,
  DEFAULT_LOCALE,
  LOCALES,
  isLocale,
  type Locale,
  type MessageKey,
  type Messages,
} from "./messages";

/** The cookie the language switcher writes. Readable by the server on the next request. */
export const LOCALE_COOKIE = "siembiot-locale";

export type Values = Record<string, string | number>;

/**
 * Substitutes `{name}` placeholders.
 *
 * An unknown placeholder is left as written rather than replaced with "undefined": a
 * visible `{count}` in the interface is a bug report, whereas the word "undefined" in
 * the middle of a sentence looks like it might be someone's data.
 */
export function interpolate(template: string, values?: Values): string {
  if (!values) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in values ? String(values[name]) : whole,
  );
}

export function translate(locale: Locale, key: MessageKey, values?: Values): string {
  const catalogue: Messages = CATALOGUES[locale] ?? CATALOGUES[DEFAULT_LOCALE];
  return interpolate(catalogue[key] ?? CATALOGUES[DEFAULT_LOCALE][key] ?? key, values);
}

export type Translator = (key: MessageKey, values?: Values) => string;

export function translatorFor(locale: Locale): Translator {
  return (key, values) => translate(locale, key, values);
}

/**
 * The BCP 47 tag for a locale. `ro` and `en` are already valid tags, but the mapping is
 * explicit so a future locale like `ro-MD` cannot silently become an invalid `lang`
 * attribute or a wrong date format.
 */
export const LANGUAGE_TAGS: Record<Locale, string> = { ro: "ro-RO", en: "en-GB" };

export function formatDateTime(locale: Locale, value: string | Date): string {
  const date = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(LANGUAGE_TAGS[locale], {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

/**
 * Percentages and scores. Romanian writes 43,3 where English writes 43.3, and a score
 * shown with the wrong separator reads as a different number.
 */
export function formatNumber(locale: Locale, value: number, fractionDigits = 1): string {
  return new Intl.NumberFormat(LANGUAGE_TAGS[locale], {
    minimumFractionDigits: 0,
    maximumFractionDigits: fractionDigits,
  }).format(value);
}

/**
 * Picks the reader's language out of a pair the API returned in both.
 *
 * Check titles and rationales come from the versioned policy catalogue rather than
 * from the message files, so that the words in a finding always match the policy that
 * produced it.
 */
export function pickLocalized(locale: Locale, ro: string, en: string): string {
  return locale === "en" ? en : ro;
}

/**
 * Chooses a locale from an `Accept-Language` header.
 *
 * Deliberately crude -- first supported tag wins, quality values ignored. It is only a
 * first guess for somebody who has never chosen: once they use the switcher, the
 * cookie decides and this is not consulted again.
 */
export function localeFromAcceptLanguage(header: string | null | undefined): Locale | null {
  if (!header) return null;
  for (const part of header.split(",")) {
    const tag = part.split(";")[0]?.trim().toLowerCase();
    if (!tag) continue;
    const base = tag.split("-")[0];
    if (base === "ro" || base === "en") return base;
  }
  return null;
}
