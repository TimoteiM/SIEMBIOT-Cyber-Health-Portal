import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DomainDetail from "./organizations/[organizationId]/domains/[domainId]/domain-detail";
import { apiRequest, loadSession } from "../lib/secure-client";

vi.mock("../lib/secure-client", () => ({
  ApiError: class ApiError extends Error {},
  apiRequest: vi.fn(),
  loadSession: vi.fn(),
}));

const domain = {
  contract_version: "v1",
  id: "11111111-1111-4111-8111-111111111111",
  organization_id: "22222222-2222-4222-8222-222222222222",
  canonical_name: "example.com",
  unicode_display: "example.com",
  registrable_domain: "example.com",
  warnings: [],
  ownership_state: "verified",
  created_at: "2026-08-03T10:00:00Z",
};

describe("domain verification and authorization flow", () => {
  beforeEach(() => {
    vi.mocked(loadSession).mockResolvedValue({} as never);
    vi.mocked(apiRequest).mockImplementation(async (path, init) => {
      if (path.endsWith("/authorizations")) return [];
      if (path.endsWith("/emergency-controls")) return [];
      if (path.endsWith("/domains/11111111-1111-4111-8111-111111111111")) return domain;
      if (path.endsWith("/challenges") && init?.method === "POST") {
        return {
          contract_version: "v1",
          id: "33333333-3333-4333-8333-333333333333",
          domain_id: domain.id,
          method: "dns_txt",
          state: "pending",
          expires_at: "2026-08-03T10:15:00Z",
          attempts_remaining: 5,
          verification_location: "_siembiot-verify.example.com",
          verification_token: "siembiot-v1=one-time-secret-value-for-test",
        };
      }
      throw new Error(`Unexpected request: ${path}`);
    });
  });

  it("shows server state, explicit consent, and one-time verification instructions", async () => {
    render(<DomainDetail organizationId={domain.organization_id} domainId={domain.id} />);
    expect(await screen.findByText("Domeniu verificat")).toBeTruthy();
    expect(screen.getByText(/Autorizez exclusiv verificarea pasivă/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Creează dovada" }));
    expect(await screen.findByText("siembiot-v1=one-time-secret-value-for-test")).toBeTruthy();
    expect(screen.getByText(/înregistrare TXT/)).toBeTruthy();
    expect(screen.getByText(/mai sunt 5 încercări/)).toBeTruthy();
  });
});
