import { describe, expect, it } from "vitest";

import { challengeInstructionKey, ownershipPresentation } from "./domain-state";
import { CATALOGUES, LOCALES, translate } from "./i18n";

/**
 * This module decides which verification state deserves which wording and tone. It
 * used to return finished Romanian sentences, which made the decision and the language
 * the same value and the whole file untranslatable. It now returns message keys, so
 * these tests check the mapping and that both catalogues can render it.
 */
describe("domain state presentation", () => {
  it("distinguishes pending, verified, and suspended security states", () => {
    expect(ownershipPresentation("pending").titleKey).toBe("domainState.pending.title");
    expect(ownershipPresentation("verified").titleKey).toBe("domainState.verified.title");
    expect(ownershipPresentation("revoked").tone).toBe("danger");
  });

  it("names a tone for every state the API can report", () => {
    // A state without a presentation renders as undefined rather than as a warning,
    // which is the failure mode where a revoked domain looks unremarkable.
    for (const state of [
      "pending",
      "verified",
      "expired",
      "failed",
      "revoked",
      "reverification_required",
    ] as const) {
      expect(ownershipPresentation(state).tone).toBeTruthy();
    }
  });

  it("gives fixed DNS and HTTPS instructions in both languages", () => {
    const location = "_tyche-verify.example.com";
    for (const locale of LOCALES) {
      const dns = translate(locale, challengeInstructionKey("dns_txt"), { location });
      const https = translate(locale, challengeInstructionKey("https_file"), { location });
      expect(dns).toContain(location);
      expect(https).toContain(location);
      expect(dns).not.toBe(https);
    }
    expect(translate("ro", challengeInstructionKey("dns_txt"), { location })).toContain("TXT");
    expect(translate("en", challengeInstructionKey("https_file"), { location })).toContain("HTTPS");
  });

  it("has a translation for every state in every language", () => {
    for (const locale of LOCALES) {
      for (const state of ["pending", "verified", "expired", "failed", "revoked"] as const) {
        const presentation = ownershipPresentation(state);
        expect(CATALOGUES[locale][presentation.titleKey]).toBeTruthy();
        expect(CATALOGUES[locale][presentation.detailKey]).toBeTruthy();
      }
    }
  });
});
