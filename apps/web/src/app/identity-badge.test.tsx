import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AppShell from "./shell";
import { DEV_IDENTITY_COOKIE } from "../lib/dev-accounts";

/**
 * The way back out of an identity.
 *
 * This matters because the landing page sends anybody holding the identity cookie
 * straight into the application. Without a control that drops it, the first account
 * chosen would be the only one reachable without clearing site data by hand -- and the
 * two accounts exist precisely so the platform view and the client view can be compared.
 */

vi.mock("next/navigation", () => ({
  usePathname: () => "/onboarding",
  // The shell renders the language switcher, which asks for a router.
  useRouter: () => ({ refresh: () => {}, push: () => {}, replace: () => {} }),
}));

function setCookie(value: string): void {
  document.cookie = `${DEV_IDENTITY_COOKIE}=${value}; path=/`;
}

describe("the identity control in the shell", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "development");
    setCookie("");
  });

  afterEach(() => {
    // Without this each render stays in the document, and a later assertion that
    // something is absent matches the previous test's markup instead.
    cleanup();
    vi.unstubAllEnvs();
  });

  it("names who you are working as", async () => {
    setCookie("platform-admin");
    render(<AppShell>content</AppShell>);

    // Read after mount, because the server cannot see document.cookie and rendering the
    // name during the first pass would be markup the client immediately contradicts.
    await waitFor(() => expect(screen.getByText(/Mihai Constantin/)).toBeTruthy());
  });

  it("offers a way to change identity", async () => {
    setCookie("demo-primar");
    render(<AppShell>content</AppShell>);

    await waitFor(() => expect(screen.getByRole("button", { name: /identit/i })).toBeTruthy());
  });

  it("shows nothing when no identity has been chosen", async () => {
    render(<AppShell>content</AppShell>);

    await waitFor(() => expect(screen.queryByText(/Mihai Constantin/)).toBeNull());
    expect(screen.queryByText(/Elena Marinescu/)).toBeNull();
  });

  it("shows nothing outside development", async () => {
    // It undoes the development sign-in. Offering to "change identity" where identity is
    // established by a gateway would be a button that cannot do what it says.
    vi.stubEnv("NODE_ENV", "production");
    setCookie("platform-admin");
    render(<AppShell>content</AppShell>);

    await waitFor(() => expect(screen.queryByText(/Mihai Constantin/)).toBeNull());
  });
});
