import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import SignInPage from "./page";

/**
 * What the first page shows, in each build.
 *
 * The root redirects here in every build, so this page is what a person meets on
 * arrival — including in a real deployment. That is the whole reason these assertions
 * exist: the development identity picker sets a cookie that only the development
 * middleware reads, so the same form in production leads to a page that answers 401. A
 * dead end shaped like a login is worse than no page at all, and worse still on a portal
 * for public institutions, where a form asking for a password is a phishing lesson
 * taught by the real thing.
 *
 * So the negative assertion is the important one, and it is written against the input
 * type rather than against copy: a password field is what a person recognises as a login,
 * whatever the surrounding words say.
 */

vi.mock("next/navigation", () => ({
  usePathname: () => "/sign-in",
  useRouter: () => ({ refresh: () => {}, push: () => {}, replace: () => {} }),
}));

function passwordFields(): Element[] {
  return Array.from(document.querySelectorAll('input[type="password"]'));
}

describe("the sign-in page in a development build", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "development");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("offers the identity picker", () => {
    render(<SignInPage />);

    expect(passwordFields()).toHaveLength(1);
  });

  it("says on its face that it is not authentication", () => {
    // The picker is allowed to exist only because it admits what it is. If this text
    // were ever dropped, what remains is a login form that does not log in.
    render(<SignInPage />);

    expect(screen.getByRole("note")).toBeTruthy();
  });
});

describe("the sign-in page in a production build", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("renders no password field", () => {
    // The assertion this file was written for.
    render(<SignInPage />);

    expect(passwordFields()).toHaveLength(0);
  });

  it("renders no form to submit at all", () => {
    render(<SignInPage />);

    expect(document.querySelectorAll("form")).toHaveLength(0);
  });

  it("does not name the development accounts", () => {
    // `admin` and `expert` are in the repository and are not secret. Listing them on a
    // deployment would still be an invitation to try them somewhere they might work.
    render(<SignInPage />);

    expect(document.body.textContent).not.toContain("admin");
    expect(document.body.textContent).not.toContain("expert");
  });

  it("says where authentication actually happened", () => {
    // Not merely the absence of a form: somebody who arrives here needs to know that
    // identity is established by their organization's platform before the request
    // reaches this portal, or the page is a blank wall.
    render(<SignInPage />);

    const text = document.body.textContent ?? "";
    expect(text.length).toBeGreaterThan(40);
    expect(screen.getByRole("heading", { level: 1 })).toBeTruthy();
  });

  it("offers the way into the workspace", () => {
    // Anybody arriving here in a deployment was already authenticated upstream, so the
    // page has to lead somewhere rather than being a terminus.
    render(<SignInPage />);

    const links = Array.from(document.querySelectorAll("a[href]"));
    expect(links.some((link) => link.getAttribute("href") === "/onboarding")).toBe(true);
  });
});
