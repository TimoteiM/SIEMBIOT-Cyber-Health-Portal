import type { MessageKey } from "./i18n";
import { ApiError } from "./secure-client";

/**
 * Turns a failure into a message key the reader's language has a sentence for.
 *
 * The API's `message` field is English developer text -- "The requested resource was
 * not found." -- and the interface was showing it verbatim, so a Romanian user got
 * Romanian everywhere except at the moment something went wrong. The API's `code` is
 * the stable part of the contract; the words belong to whoever is reading.
 *
 * An unrecognised code falls back to the caller's own key rather than to a generic
 * apology, because the calling screen knows what the reader was trying to do and can
 * say something more useful than "that failed".
 */
export function apiErrorKey(error: unknown, fallback: MessageKey): MessageKey {
  if (!(error instanceof ApiError)) return fallback;

  const key = `error.${error.code}` as MessageKey;
  return KNOWN_ERROR_KEYS.has(key) ? key : fallback;
}

/**
 * Codes with a translated sentence. Listed explicitly rather than derived, so adding a
 * code to the API without translating it fails a test instead of quietly showing the
 * reader a raw identifier.
 */
const KNOWN_ERROR_KEYS: ReadonlySet<MessageKey> = new Set<MessageKey>([
  "error.not_found",
  "error.forbidden",
  "error.validation_error",
  "error.request_rejected",
  "error.internal_error",
  "error.unauthorized",
  "error.ownership_not_verified",
  "error.methodology_unavailable",
  "error.no_scored_assessment",
  "error.unsupported_locale",
]);

export { KNOWN_ERROR_KEYS };
