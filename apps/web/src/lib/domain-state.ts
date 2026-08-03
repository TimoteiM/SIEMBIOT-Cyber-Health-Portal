import type { components } from "@siembiot/contracts/private-api-v1";

type OwnershipState = components["schemas"]["DomainResponse"]["ownership_state"];
type ChallengeMethod = components["schemas"]["DomainChallengeCreate"]["method"];

export type StatePresentation = {
  title: string;
  detail: string;
  tone: "neutral" | "success" | "warning" | "danger";
};

const PRESENTATIONS: Record<OwnershipState, StatePresentation> = {
  pending: {
    title: "Verificare în așteptare",
    detail: "Dovada controlului asupra domeniului nu a fost încă validată.",
    tone: "neutral",
  },
  verified: {
    title: "Domeniu verificat",
    detail: "Serverul a confirmat dovada. Reverificarea periodică rămâne obligatorie.",
    tone: "success",
  },
  expired: {
    title: "Verificare expirată",
    detail: "Creează o provocare nouă pentru a relua verificarea.",
    tone: "warning",
  },
  failed: {
    title: "Verificare nereușită",
    detail: "Bugetul de încercări a fost consumat. Creează o provocare nouă.",
    tone: "danger",
  },
  revoked: {
    title: "Acces suspendat",
    detail: "Dovada a fost revocată; nicio evaluare nu este autorizată.",
    tone: "danger",
  },
  reverification_required: {
    title: "Reverificare necesară",
    detail: "Confirmă din nou controlul înainte de orice operațiune ulterioară.",
    tone: "warning",
  },
};

export function ownershipPresentation(state: OwnershipState): StatePresentation {
  return PRESENTATIONS[state];
}

export function challengeInstructions(method: ChallengeMethod, location: string): string {
  if (method === "dns_txt") {
    return `Publică valoarea exactă într-o înregistrare TXT la ${location}.`;
  }
  return `Publică valoarea exactă prin HTTPS la ${location}; redirecționările sunt verificate strict.`;
}
