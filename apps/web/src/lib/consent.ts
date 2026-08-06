import type { Locale } from "./i18n";

/**
 * The words somebody actually agrees to when authorizing an assessment.
 *
 * Kept out of the message catalogue on purpose. Everything in that file is interface
 * chrome that can be reworded freely; this is a statement of consent whose exact text
 * is digested and stored against the authorization, so rewording it changes what the
 * record says a person agreed to.
 *
 * The version tag carries the language (`ro-v1`, `en-v1`) because a translation is a
 * different statement, not the same statement in different letters. If the English and
 * Romanian wordings ever diverge in meaning, the stored version is what tells an
 * auditor which one was shown.
 *
 * **Changing any wording here requires a new version number.** The digest of the old
 * text is already stored against existing authorizations; editing in place would leave
 * those records pointing at wording nobody was ever shown.
 *
 * The English text below is a translation of the reviewed Romanian original and has
 * not itself been through legal review.
 */
export type Consent = { version: string; text: string };

const CONSENT: Record<Locale, Consent> = {
  ro: {
    version: "ro-v1",
    text:
      "Autorizez exclusiv verificarea pasivă și verificarea proprietății pentru domeniul " +
      "selectat, în intervalul indicat. Înțeleg că autorizarea poate fi revocată imediat.",
  },
  en: {
    version: "en-v1",
    text:
      "I authorize passive assessment and ownership verification only, for the selected " +
      "domain and within the stated period. I understand the authorization can be revoked " +
      "immediately.",
  },
};

export function consentFor(locale: Locale): Consent {
  return CONSENT[locale] ?? CONSENT.ro;
}
