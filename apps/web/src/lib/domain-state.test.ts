import { describe, expect, it } from "vitest";

import { challengeInstructions, ownershipPresentation } from "./domain-state";

describe("Romanian domain state presentation", () => {
  it("distinguishes pending, verified, and suspended security states", () => {
    expect(ownershipPresentation("pending").title).toBe("Verificare în așteptare");
    expect(ownershipPresentation("verified").title).toBe("Domeniu verificat");
    expect(ownershipPresentation("revoked").tone).toBe("danger");
  });

  it("gives fixed DNS and HTTPS instructions without weakening verification", () => {
    expect(challengeInstructions("dns_txt", "_tyche-verify.example.com")).toContain(
      "înregistrare TXT",
    );
    expect(
      challengeInstructions(
        "https_file",
        "https://example.com/.well-known/tyche-verification.txt",
      ),
    ).toContain("HTTPS");
  });
});
