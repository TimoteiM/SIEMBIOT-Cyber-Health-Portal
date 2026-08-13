import axe, { type AxeResults, type Result } from "axe-core";

/**
 * Running axe over rendered markup, with the two guards that make the result mean
 * something.
 *
 * **What this cannot do, stated first, because the gap is the dangerous part.** These
 * tests run in jsdom, which implements the DOM and no layout: nothing has a position, a
 * size or a computed colour. So axe cannot evaluate colour contrast, focus visibility,
 * target size, or anything else that depends on how the page is actually painted. axe
 * reports those as *incomplete* rather than passing, and this module surfaces that
 * distinction rather than flattening it into a green tick.
 *
 * That is precisely why the manual keyboard and screen-reader pass Milestone 10 asks for
 * is still outstanding and is not made redundant by this file. What is automated here is
 * structure and semantics: labels, roles, names, heading order, landmark structure, valid
 * ARIA. Those are the failures that are cheap to introduce and tedious to find by hand,
 * which is a good division of labour -- but calling it "accessibility testing" without
 * the rest would be the same overstatement this repository keeps hunting.
 */

/** Rules jsdom cannot decide, disabled by name rather than left to report as unknown. */
const NEEDS_LAYOUT = [
  "color-contrast",
  "target-size",
  // Both need a viewport and painted geometry. Left enabled they produce "incomplete"
  // results on every run, which trains a reader to ignore the incomplete list -- and the
  // incomplete list is where a genuinely undecidable result would hide.
] as const;

export interface AuditResult {
  violations: Result[];
  /** Checks axe could not decide here. Never counted as passes. */
  incomplete: Result[];
}

/**
 * Fail loudly when handed nothing.
 *
 * axe over an empty container reports zero violations, which is indistinguishable from a
 * clean page. A component that threw during render, or a page that returned null under
 * test conditions, would otherwise be reported as accessible.
 */
function refuseEmptyMarkup(container: Element): void {
  const elements = container.querySelectorAll("*").length;
  const text = (container.textContent ?? "").trim();

  if (elements < 3 || text.length < 10) {
    throw new Error(
      `Refusing to audit: the container has ${elements} elements and ${text.length} ` +
        "characters of text. axe reports no violations for markup that is not there, " +
        "so this would have passed while testing nothing.",
    );
  }
}

export async function audit(container: Element): Promise<AuditResult> {
  refuseEmptyMarkup(container);

  const results: AxeResults = await axe.run(container, {
    rules: Object.fromEntries(NEEDS_LAYOUT.map((rule) => [rule, { enabled: false }])),
    resultTypes: ["violations", "incomplete"],
  });

  return { violations: results.violations, incomplete: results.incomplete };
}

/** A readable failure. The default axe object is unreadable in a test report. */
export function describe(violations: Result[]): string {
  return violations
    .map((violation) => {
      const where = violation.nodes.map((node) => node.html).join("\n      ");
      return `  ${violation.id} (${violation.impact}): ${violation.help}\n      ${where}`;
    })
    .join("\n");
}
