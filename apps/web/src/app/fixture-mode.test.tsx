import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import RootLayout from "./layout";

describe("fixture-only status", () => {
  it("is persistently visible in the root layout", () => {
    render(<RootLayout><div>Conținut</div></RootLayout>);
    const banner = screen.getByRole("status", { name: "Mod de validare cu date fixture" });
    expect(banner.textContent).toContain("MOD FIXTURE — NU ESTE O EVALUARE LIVE");
    expect(banner.textContent).toContain("nu pot fi publicate ca rezultate reale");
    expect(screen.getByText("Conținut")).toBeTruthy();
  });
});
