import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe as group, expect, it, vi } from "vitest";

import { audit, describe } from "./audit";
import AppShell from "../app/shell";
import SignInPage from "../app/sign-in/page";
import LanguageSwitcher from "../app/language-switcher";

/**
 * Automated accessibility checks over the surfaces this platform actually renders.
 *
 * The audience is Romanian public institutions, which are bound by accessibility
 * obligations their suppliers are frequently the reason they fail. "Built to be
 * accessible" and "measured" are different claims, and until this file existed only the
 * first was true.
 *
 * **What is not covered here** is stated in `audit.ts` and matters: jsdom has no layout,
 * so colour contrast, focus visibility and target size cannot be evaluated by any test in
 * this file. Those need the manual keyboard and screen-reader pass, which remains
 * outstanding. This suite covers structure and semantics — the failures that are cheap to
 * introduce and tedious to find by hand.
 */

vi.mock("next/navigation", () => ({
  usePathname: () => "/organizations/demo",
  useRouter: () => ({ refresh: () => {}, push: () => {}, replace: () => {} }),
}));

function expectNoViolations(result: Awaited<ReturnType<typeof audit>>): void {
  expect(describe(result.violations), `\n${describe(result.violations)}`).toBe("");
}

group("the sign-in page, which is the first page anybody meets", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("has no violations as the development identity picker", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const { container } = render(<SignInPage />);

    expectNoViolations(await audit(container));
  });

  it("has no violations in a production build", async () => {
    // The variant a real institution sees. It renders no form, which removes most of
    // what axe would look at -- so the empty-markup guard in `audit` is doing real work
    // here rather than being a formality.
    vi.stubEnv("NODE_ENV", "production");
    const { container } = render(<SignInPage />);

    expectNoViolations(await audit(container));
  });
});

group("the application shell, which wraps every authenticated page", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "development");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("has no violations", async () => {
    const { container } = render(
      <AppShell>
        <h1>Conținut</h1>
        <p>Un paragraf, pentru ca regiunea principală să nu fie goală.</p>
      </AppShell>,
    );

    expectNoViolations(await audit(container));
  });

  it("names its navigation landmark", async () => {
    // Two landmarks of the same type must be distinguishable, or a screen-reader user
    // hears "navigation" twice and has to explore both to tell them apart.
    const { container } = render(
      <AppShell>
        <h1>Conținut</h1>
        <p>Un paragraf.</p>
      </AppShell>,
    );

    const navs = container.querySelectorAll("nav");
    for (const nav of navs) {
      const named =
        nav.hasAttribute("aria-label") ||
        nav.hasAttribute("aria-labelledby") ||
        navs.length === 1;
      expect(named, "a <nav> with no accessible name").toBe(true);
    }
  });
});

group("the language switcher", () => {
  afterEach(cleanup);

  it("has no violations", async () => {
    const { container } = render(
      <div>
        <LanguageSwitcher />
        <p>Comutatorul de limbă, în context.</p>
      </div>,
    );

    expectNoViolations(await audit(container));
  });
});

group("the audit itself", () => {
  afterEach(cleanup);

  it("refuses to report on markup that is not there", async () => {
    // The guard that makes every assertion above mean something. axe over an empty
    // container returns zero violations, which reads exactly like a clean page -- so a
    // component that threw during render would otherwise be reported as accessible.
    const { container } = render(<div />);

    await expect(audit(container)).rejects.toThrow(/Refusing to audit/);
  });

  it("finds a violation that is really there", async () => {
    // The mutation, kept rather than performed once by hand. Without this, every test
    // above passes identically if axe is misconfigured, scoped to the wrong node, or
    // silently returning nothing.
    const { container } = render(
      <div>
        <p>Un formular fără etichetă, pentru a verifica detectorul.</p>
        <input type="text" />
        <img src="/x.png" />
      </div>,
    );

    const result = await audit(container);

    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations.map((violation) => violation.id)).toContain("image-alt");
  });

  it("reports undecidable checks separately from passing ones", async () => {
    // jsdom cannot decide everything, and an "incomplete" result must never be read as a
    // pass. Asserting the field exists keeps that distinction visible in the API even
    // when, as here, there happens to be nothing in it.
    const { container } = render(
      <div>
        <h1>Titlu</h1>
        <p>Un paragraf suficient de lung.</p>
      </div>,
    );

    const result = await audit(container);

    expect(Array.isArray(result.incomplete)).toBe(true);
  });
});
