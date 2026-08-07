import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { components } from "@siembiot/contracts/private-api-v1";

import MaturityPanel from "./organizations/[organizationId]/maturity/maturity-panel";
import { apiRequest, loadSession } from "../lib/secure-client";

// Typed against the generated contract rather than written free-hand, so a fixture that
// drifts from what the server actually returns is a build error instead of a test that
// keeps passing against a shape nobody serves any more.
type Maturity = components["schemas"]["MaturityResponse"];

vi.mock("../lib/secure-client", () => ({
  ApiError: class ApiError extends Error {},
  apiRequest: vi.fn(),
  loadSession: vi.fn(),
}));

const ORGANIZATION = "22222222-2222-4222-8222-222222222222";

/**
 * Shaped like the real response, including the fields that carry the distinction this
 * screen exists to preserve: a declared percentage that is withheld rather than shown
 * when completeness is short, and a per-question observation kept beside the answer.
 */
function body(overrides: Partial<Maturity> = {}): Maturity {
  return {
    contract_version: "v1",
    organization_id: ORGANIZATION,
    questionnaire_id: "nis2_baseline",
    questionnaire_version: "1.0.0",
    review_status: "draft",
    notice_ro:
      "Un chestionar de autoevaluare. Răspunsurile sunt declarații ale organizației.",
    notice_en: "A self-assessment questionnaire. The answers are declarations.",
    ladder: [],
    self_declared_percentage: null,
    completeness_percentage: 6.5,
    minimum_completeness_percentage: 70,
    comparable: false,
    incomparable_reason: "insufficient_completeness",
    answered_count: 1,
    unanswered_count: 30,
    not_applicable_count: 0,
    contradicted_count: 0,
    sections: [
      {
        section_id: "hygiene_training",
        nis2_reference: "Article 21(2)(g)",
        cis_reference: null,
        title_ro: "Igiena cibernetică de bază",
        title_en: "Basic cyber hygiene",
        percentage: null,
        completeness_percentage: 0,
        questions: [
          {
            question_id: "hygiene_training.email_authentication",
            nis2_reference: "Article 21(2)(g)",
            weight: 2,
            title_ro: "Domeniile organizației sunt configurate împotriva falsificării.",
            title_en: "The domains are configured against spoofing.",
            help_ro: "SPF, DKIM și DMARC în regim de aplicare.",
            help_en: "SPF, DKIM and DMARC in enforcing mode.",
            corroborating_check_id: "B.dmarc_enforced",
            answer: null,
            evidence_reference: null,
            note: null,
            answered_at: null,
            answered_by_display_name: null,
            observed: null,
            corroboration: null,
          },
        ],
      },
    ],
    ...overrides,
  };
}

function contradicted(): Maturity {
  const document = body({
    contradicted_count: 1,
    answered_count: 25,
    unanswered_count: 6,
    completeness_percentage: 82,
    comparable: true,
    incomparable_reason: null,
    self_declared_percentage: 74.2,
  });
  const section = (document.sections ?? [])[0];
  const questions = section.questions ?? [];
  questions[0] = {
    ...questions[0],
    answer: "verified",
    observed: "problem",
    corroboration: "contradicted",
  };
  return document;
}

describe("the self-assessment", () => {
  beforeEach(() => {
    vi.mocked(loadSession).mockResolvedValue({} as never);
    vi.mocked(apiRequest).mockReset();
  });

  // There is no global setup file, so a render survives into the next test and every
  // query then matches twice. Unmounting keeps each assertion about one screen.
  afterEach(cleanup);

  it("withholds the declared result below the completeness floor", async () => {
    // A percentage beside a warning is still a percentage: readers keep the number and
    // drop the warning. So there is no number to keep.
    vi.mocked(apiRequest).mockResolvedValue(body() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    expect(await screen.findByText("Rezultat indisponibil")).toBeTruthy();
    expect(screen.getByText(/Sub 70% completitudine/)).toBeTruthy();
    // No declared figure anywhere -- withheld means withheld, not greyed out.
    expect(screen.queryByText(/Rezultat declarat de organizație: \d/)).toBeNull();
    // Completeness itself is still reported: it is a fact about the answers, not a
    // result drawn from them, and hiding it would leave no way to know what is missing.
    expect(screen.getByText(/Completitudine: 6[.,]5%/)).toBeTruthy();
  });

  it("never presents the declared result as comparable with the assessment score", async () => {
    vi.mocked(apiRequest).mockResolvedValue(contradicted() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    expect(await screen.findByText(/Rezultat declarat de organizație: 74[.,]2%/)).toBeTruthy();
    // The sentence that stops somebody averaging the two sits next to the number
    // rather than in help text on another screen.
    expect(screen.getByText(/Nu se combină cu scorul evaluării tehnice/)).toBeTruthy();
    // And no band is offered, because a band is earned by observation.
    for (const band of ["Rezilient", "Gestionat", "În dezvoltare", "Expus", "Critic"]) {
      expect(screen.queryByText(band)).toBeNull();
    }
  });

  it("says out loud that not knowing is not the same as not having", async () => {
    vi.mocked(apiRequest).mockResolvedValue(body() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    expect(await screen.findByText(/„Nu știu” nu se punctează ca „nu”/)).toBeTruthy();
    expect(screen.getByRole("option", { name: "Nu știu." })).toBeTruthy();
  });

  it("gives a contradicted claim a paragraph rather than a badge", async () => {
    vi.mocked(apiRequest).mockResolvedValue(contradicted() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    const notice = await screen.findByText(/evaluarea observă contrariul/);
    expect(notice).toBeTruthy();
    // Rendered as a note, which is what gives it the same weight as a caveat
    // elsewhere in the product rather than the weight of a status chip.
    expect(notice.closest("[role='note']")).toBeTruthy();
  });

  it("shows the questionnaire's own notice and its draft status before any question", async () => {
    vi.mocked(apiRequest).mockResolvedValue(body() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    expect(await screen.findByText(/Răspunsurile sunt declarații ale organizației/)).toBeTruthy();
    expect(screen.getByText(/nu au trecut încă printr-o revizuire de securitate/)).toBeTruthy();
  });

  it("names the legal basis for each section", async () => {
    vi.mocked(apiRequest).mockResolvedValue(body() as never);
    render(<MaturityPanel organizationId={ORGANIZATION} />);

    expect(
      await screen.findByText("NIS2, articolul 21 alineatul (2) litera (g)"),
    ).toBeTruthy();
  });

  it("sends the chosen answer and re-renders from the server's reply", async () => {
    // The server returns the whole document because one answer changes the score, the
    // completeness, and whether a score is shown at all. The client must not recompute
    // any of that: a client that recomputes a score eventually disagrees with it.
    vi.mocked(apiRequest)
      .mockResolvedValueOnce(body() as never)
      .mockResolvedValueOnce(contradicted() as never);

    render(<MaturityPanel organizationId={ORGANIZATION} />);
    const select = await screen.findByLabelText(
      /Domeniile organizației sunt configurate împotriva falsificării/,
    );
    fireEvent.change(select, { target: { value: "verified" } });

    expect(await screen.findByText(/evaluarea observă contrariul/)).toBeTruthy();
    const call = vi.mocked(apiRequest).mock.calls[1];
    expect(call[0]).toContain(
      "/maturity/answers/hygiene_training.email_authentication",
    );
    expect(call[1]?.method).toBe("PUT");
    expect(JSON.parse(String(call[1]?.body))).toEqual({ answer: "verified" });
  });
});
