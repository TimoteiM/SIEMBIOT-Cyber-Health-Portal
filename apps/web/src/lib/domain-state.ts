import type { components } from "@siembiot/contracts/private-api-v1";

import type { MessageKey } from "./i18n";

type OwnershipState = components["schemas"]["DomainResponse"]["ownership_state"];
type ChallengeMethod = components["schemas"]["DomainChallengeCreate"]["method"];

/**
 * How a verification state should read, as message keys rather than sentences.
 *
 * This module decides *which* state deserves which wording and tone; the words
 * themselves belong to whoever is reading. Returning finished Romanian sentences from
 * here is what made the whole file untranslatable -- the decision and the language
 * were the same value.
 */
export type StatePresentation = {
  titleKey: MessageKey;
  detailKey: MessageKey;
  tone: "neutral" | "success" | "warning" | "danger";
};

const PRESENTATIONS: Record<OwnershipState, StatePresentation> = {
  pending: {
    titleKey: "domainState.pending.title",
    detailKey: "domainState.pending.detail",
    tone: "neutral",
  },
  verified: {
    titleKey: "domainState.verified.title",
    detailKey: "domainState.verified.detail",
    tone: "success",
  },
  expired: {
    titleKey: "domainState.expired.title",
    detailKey: "domainState.expired.detail",
    tone: "warning",
  },
  failed: {
    titleKey: "domainState.failed.title",
    detailKey: "domainState.failed.detail",
    tone: "danger",
  },
  revoked: {
    titleKey: "domainState.revoked.title",
    detailKey: "domainState.revoked.detail",
    tone: "danger",
  },
  reverification_required: {
    titleKey: "domainState.reverification_required.title",
    detailKey: "domainState.reverification_required.detail",
    tone: "warning",
  },
};

export function ownershipPresentation(state: OwnershipState): StatePresentation {
  return PRESENTATIONS[state];
}

/** Which instruction applies. The location is interpolated by the caller's translator. */
export function challengeInstructionKey(method: ChallengeMethod): MessageKey {
  return method === "dns_txt"
    ? "domainState.instructionsDns"
    : "domainState.instructionsHttps";
}
