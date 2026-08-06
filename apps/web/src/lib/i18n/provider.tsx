"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";

import {
  DEFAULT_LOCALE,
  formatDateTime,
  formatNumber,
  pickLocalized,
  translatorFor,
  type Locale,
  type Translator,
} from "./index";

type Localization = {
  locale: Locale;
  t: Translator;
  formatDateTime: (value: string | Date) => string;
  formatNumber: (value: number, fractionDigits?: number) => string;
  pick: (ro: string, en: string) => string;
};

/**
 * Defaults to Romanian rather than throwing when no provider is present.
 *
 * A component rendered outside the provider is a wiring mistake, and the useful
 * behaviour is that it shows Romanian text rather than crashing the page it is on.
 * The test suite asserts that every route is wrapped, so the mistake is caught there
 * instead of at a user's expense.
 */
const LocalizationContext = createContext<Localization | null>(null);

export function LocalizationProvider({
  locale,
  children,
}: {
  locale: Locale;
  children: ReactNode;
}) {
  const value = useMemo<Localization>(
    () => ({
      locale,
      t: translatorFor(locale),
      formatDateTime: (input) => formatDateTime(locale, input),
      formatNumber: (input, fractionDigits) => formatNumber(locale, input, fractionDigits),
      pick: (ro, en) => pickLocalized(locale, ro, en),
    }),
    [locale],
  );
  return (
    <LocalizationContext.Provider value={value}>{children}</LocalizationContext.Provider>
  );
}

export function useLocalization(): Localization {
  const value = useContext(LocalizationContext);
  if (value) return value;
  return {
    locale: DEFAULT_LOCALE,
    t: translatorFor(DEFAULT_LOCALE),
    formatDateTime: (input) => formatDateTime(DEFAULT_LOCALE, input),
    formatNumber: (input, fractionDigits) =>
      formatNumber(DEFAULT_LOCALE, input, fractionDigits),
    pick: (ro) => ro,
  };
}
