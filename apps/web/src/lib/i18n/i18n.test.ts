import { describe, expect, it } from "vitest";

import { KNOWN_ERROR_KEYS } from "../api-errors";
import { consentFor } from "../consent";
import {
  CATALOGUES,
  DEFAULT_LOCALE,
  formatDateTime,
  formatNumber,
  interpolate,
  isLocale,
  LANGUAGE_TAGS,
  localeFromAcceptLanguage,
  LOCALES,
  pickLocalized,
  translate,
} from "./index";

/**
 * The failure this suite exists to prevent is a page that is *mostly* translated.
 * A missing key is not a blank space -- it is one language appearing inside another,
 * which reads as carelessness about the reader rather than as a bug.
 */
describe("the message catalogues", () => {
  const [reference, ...others] = LOCALES;

  it("agree on every key", () => {
    const expected = Object.keys(CATALOGUES[reference]).sort();
    for (const locale of others) {
      expect(Object.keys(CATALOGUES[locale]).sort()).toEqual(expected);
    }
  });

  it.each(LOCALES)("has no empty message in %s", (locale) => {
    for (const [key, value] of Object.entries(CATALOGUES[locale])) {
      expect(value.trim(), `${locale}:${key}`).not.toBe("");
    }
  });

  it("does not leave Romanian diacritics in the English catalogue", () => {
    // Not proof of translation, but it catches the common accident: a key copied
    // across and never rewritten.
    const romanianOnly = /[ăâîșțĂÂÎȘȚ]/;
    for (const [key, value] of Object.entries(CATALOGUES.en)) {
      // The language names are deliberately shown in their own language.
      if (key === "app.languageRomanian") continue;
      expect(romanianOnly.test(value), `${key}: ${value}`).toBe(false);
    }
  });

  it("keeps the same placeholders in every language", () => {
    // A translation that drops {count} silently loses a number the sentence needs.
    const placeholders = (text: string) => (text.match(/\{(\w+)\}/g) ?? []).sort();
    for (const key of Object.keys(CATALOGUES[reference]) as (keyof typeof CATALOGUES.ro)[]) {
      const expected = placeholders(CATALOGUES[reference][key]);
      for (const locale of others) {
        expect(placeholders(CATALOGUES[locale][key]), `${locale}:${key}`).toEqual(expected);
      }
    }
  });

  it("has a translated sentence for every error code the client maps", () => {
    for (const key of KNOWN_ERROR_KEYS) {
      for (const locale of LOCALES) {
        expect(CATALOGUES[locale][key], `${locale}:${key}`).toBeTruthy();
      }
    }
  });
});

describe("interpolation", () => {
  it("substitutes named values", () => {
    expect(interpolate("{a} of {b}", { a: 3, b: 13 })).toBe("3 of 13");
  });

  it("leaves an unknown placeholder visible rather than writing undefined", () => {
    // A visible {count} is a bug report. The word "undefined" in a sentence looks like
    // it might be somebody's data.
    expect(interpolate("{count} items", {})).toBe("{count} items");
  });

  it("ignores a template with nothing to substitute", () => {
    expect(interpolate("plain")).toBe("plain");
  });
});

describe("locale resolution", () => {
  it("accepts only supported locales", () => {
    expect(isLocale("ro")).toBe(true);
    expect(isLocale("en")).toBe(true);
    expect(isLocale("fr")).toBe(false);
    expect(isLocale(undefined)).toBe(false);
  });

  it("reads a browser preference", () => {
    expect(localeFromAcceptLanguage("en-GB,en;q=0.9")).toBe("en");
    expect(localeFromAcceptLanguage("ro-RO,ro;q=0.9,en;q=0.8")).toBe("ro");
  });

  it("returns nothing when no supported language is offered", () => {
    // The caller falls back to Romanian; returning "ro" here would hide the
    // difference between "asked for Romanian" and "asked for something we lack".
    expect(localeFromAcceptLanguage("fr-FR,de;q=0.8")).toBeNull();
    expect(localeFromAcceptLanguage(null)).toBeNull();
  });

  it("defaults to Romanian", () => {
    expect(DEFAULT_LOCALE).toBe("ro");
  });
});

describe("formatting", () => {
  it("uses the decimal separator of the language", () => {
    // 43.3 and 43,3 are the same number only if you know which convention is in play.
    expect(formatNumber("ro", 43.3)).toContain(",");
    expect(formatNumber("en", 43.3)).toContain(".");
  });

  it("formats dates per locale and survives a bad value", () => {
    const iso = "2026-08-06T09:15:00Z";
    expect(formatDateTime("ro", iso)).not.toBe("");
    expect(formatDateTime("en", iso)).not.toBe("");
    expect(formatDateTime("ro", "not a date")).toBe("");
  });

  it("maps every locale to a valid language tag", () => {
    for (const locale of LOCALES) {
      expect(() => new Intl.DateTimeFormat(LANGUAGE_TAGS[locale])).not.toThrow();
    }
  });
});

describe("catalogue-sourced text", () => {
  it("picks the reader's language from a bilingual pair", () => {
    // Check titles come from the versioned policy catalogue, not from these files, so
    // the words in a finding always match the policy that produced it.
    expect(pickLocalized("ro", "titlu", "title")).toBe("titlu");
    expect(pickLocalized("en", "titlu", "title")).toBe("title");
  });
});

describe("consent", () => {
  it("tags the version with the language", () => {
    // A translation is a different statement, not the same statement in other letters.
    // The stored version is what tells an auditor which wording was shown.
    expect(consentFor("ro").version).toBe("ro-v1");
    expect(consentFor("en").version).toBe("en-v1");
  });

  it("gives different wording per language", () => {
    expect(consentFor("ro").text).not.toBe(consentFor("en").text);
    for (const locale of LOCALES) {
      expect(consentFor(locale).text.length).toBeGreaterThan(20);
    }
  });
});

describe("translate", () => {
  it("renders a known key in both languages", () => {
    expect(translate("ro", "onboarding.submit")).toBe("Continuă");
    expect(translate("en", "onboarding.submit")).toBe("Continue");
  });

  it("interpolates values", () => {
    expect(translate("en", "assessments.coverage", { percent: 91.5 })).toContain("91.5");
  });
});
