import { describe, expect, it } from "vitest";

/**
 * The slug rule the onboarding form enforces, kept beside the tests that pin it.
 *
 * Two things went wrong here at once and each hid the other. The pattern allowed a
 * trailing hyphen the server rejects, so a valid-looking slug came back a 422; and it
 * was written with a bare `-` at the end of a character class, which browsers now
 * compile under the RegExp `v` flag and refuse outright. An invalid pattern does not
 * fail safe -- the browser throws while parsing it and the field ends up with no
 * validation at all, which is how the first bug stayed invisible.
 */
const SLUG_PATTERN = "[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?";

/** How a browser actually compiles the `pattern` attribute: anchored, `v` flag. */
function browserRegExp(): RegExp {
  return new RegExp(`^(?:${SLUG_PATTERN})$`, "v");
}

describe("the organization slug pattern", () => {
  it("compiles under the flag browsers use for pattern attributes", () => {
    // The original `[a-z0-9-]` throws here. That is the whole point of this test:
    // a pattern that cannot be compiled silently disables client validation.
    expect(() => browserRegExp()).not.toThrow();
  });

  it.each(["tarom", "a", "primaria-sector-1", "a1", "x-1-y"])("accepts %s", (slug) => {
    expect(browserRegExp().test(slug)).toBe(true);
  });

  it.each([
    ["tarom-", "a trailing hyphen, which the server rejects"],
    ["-tarom", "a leading hyphen"],
    ["TAROM", "upper case"],
    ["ta rom", "a space"],
    ["tarom_1", "an underscore"],
    ["", "nothing at all"],
  ])("rejects %s (%s)", (slug) => {
    expect(browserRegExp().test(slug)).toBe(false);
  });

  it("agrees with the server's rule on length", () => {
    // The server allows 63 characters; the client must not be stricter or looser,
    // because either way somebody types something the other end disagrees with.
    expect(browserRegExp().test("a".repeat(63))).toBe(true);
    expect(browserRegExp().test("a".repeat(64))).toBe(false);
  });
});
