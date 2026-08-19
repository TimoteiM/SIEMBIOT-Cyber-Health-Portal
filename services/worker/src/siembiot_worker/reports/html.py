"""The assessment report, as one self-contained HTML file.

Self-contained deliberately: no stylesheet link, no font URL, no image host. A report is
opened from a downloads folder, forwarded, and read on a machine that may have no route
to this platform -- and a page that fetches anything tells whoever hosts that thing when
a confidential document was opened and by whom.

Every string that came from evidence goes through the element tree in `markup`, which
escapes on serialization. There is no path in this module that concatenates untrusted
text into markup.
"""

from __future__ import annotations

from datetime import datetime

from siembiot_worker.reports.document import (
    SEVERITY_ORDER,
    ReportDocument,
    ReportEvidence,
    ReportFinding,
)
from siembiot_worker.reports.markup import Element, Node, Raw, document, element

LOCALES = ("ro", "en")
DEFAULT_LOCALE = "ro"

#: Marked on the page itself, not only in the covering e-mail. A printed page separated
#: from the message that carried it should still say what it is.
_TEXT: dict[str, dict[str, str]] = {
    "ro": {
        "confidential": "CONFIDENȚIAL",
        "confidential_note": (
            "Acest raport descrie slăbiciuni ale unei instituții publice. Distribuie-l "
            "doar persoanelor care au nevoie de el pentru a le remedia."
        ),
        "title": "Raport de igienă cibernetică",
        "organization": "Instituție",
        "domain": "Domeniu",
        "generated": "Generat la",
        "observed": "Observat la",
        "score": "Scor",
        "band": "Nivel",
        "band_withheld": (
            "Nivelul nu este acordat: acoperirea este sub pragul metodologiei. Scorul "
            "rămâne, dar este calculat pe mai puține dovezi decât cere o concluzie."
        ),
        "pillars": "Pe domenii de evaluare",
        "no_pillar_score": "fără scor",
        "weight": "pondere",
        "impact": "Cât de afectată este instituția",
        "impact_none": "Nicio slăbiciune identificată în verificările efectuate.",
        "impact_lead": (
            "Fiecare slăbiciune de mai jos este o cale prin care cineva ar putea "
            "ajunge la instituție. Cele critice și ridicate se remediază primele."
        ),
        "scale_worst": "Critic",
        "scale_best": "Rezilient",
        "score_of_100": "din 100",
        "score_attribution": (
            "Scor obținut prin metodologia de igienă cibernetică externă a acestei platforme "
            "(versiunea {methodology}), aplicată dovezilor observabile public. Nu este o măsurare "
            "directă a securității instituției."
        ),
        "coverage": "Verificări efectuate",
        "coverage_meaning": (
            "{coverage}% dintre verificările aplicabile ale metodologiei au produs un rezultat, "
            "ponderat după importanța fiecărei verificări. Nu se referă la cât din infrastructura "
            "instituției a fost analizată."
        ),
        "legend": "Cum se citesc culorile",
        "legend_direction": "100 este cel mai bun rezultat, 0 cel mai slab.",
        "importance": "importanță",
        "of_the_score": "din scor",
        "how_scored_heading": "Cum a fost calculat scorul",
        "how_scored": (
            "Fiecare verificare primește un factor — îndeplinită 1, parțial 0,5, neîndeplinită 0 "
            "— iar domeniile de mai sus se combină după ponderile arătate. Verificările "
            "neconcludente nu scad scorul; ele reduc doar procentul de verificări efectuate."
        ),
        "cap_heading": "De ce scorul a fost limitat",
        "cap_explained": (
            "Metodologia limitează scorul la {ceiling} din 100 când această situație este "
            "observată cu certitudine ridicată. Fără această limită, scorul ar fi fost "
            "{uncapped}."
        ),
        "importance_high": "ridicată",
        "importance_medium": "medie",
        "importance_low": "scăzută",
        "no_pillar_score_why": "niciun furnizor de reputație nu este configurat",
        "no_pillar_score_generic": "nu au existat verificări concludente în această zonă",
        "band.resilient": "Rezilient",
        "band.managed": "Gestionat",
        "band.developing": "În dezvoltare",
        "band.exposed": "Expus",
        "band.critical": "Critic",
        "pillar.dns": "DNS",
        "pillar.email": "E-mail",
        "pillar.web_tls": "Web și TLS",
        "pillar.attack_surface": "Suprafață de atac",
        "pillar.reputation": "Reputație",
        "pillar.exposure_hygiene": "Igiena expunerii",
        "findings": "Ce trebuie remediat",
        "no_findings": "Nu a fost identificată nicio slăbiciune în verificările efectuate.",
        "requirement_unmet": "Cerință neîndeplinită",
        "affects": "Se referă la",
        "why": "De ce contează",
        "evidence_heading": "Ce am observat",
        "checked_heading": "Ce am verificat",
        "assets_heading": "Nume descoperite public",
        "assets_note": (
            "Găsite în surse publice (jurnale de certificate, DNS). Nu sunt active confirmate: "
            "organizația decide ce îi aparține. Indicele arată cât de puternică este legătura cu "
            "domeniul evaluat."
        ),
        "asset_confidence": "indice",
        "asset_rest": "Vezi restul numelor",
        "asset_shared": "pe găzduire partajată",
        "basis.authorized_domain": "domeniul autorizat însuși",
        "basis.subdomain_of_authorized_domain": "subdomeniu al domeniului autorizat",
        "basis.unrelated_name": "nume fără legătură demonstrată",
        "basis.shared_address": "aceeași adresă IP",
        "insights_heading": "Interpretarea automată a dovezilor",
        "insight.measured": "măsurat",
        "insight.inferred": "dedus",
        "insight.recommended": "recomandare",
        "insights_evidence": "Vezi dovada",
        "checked_ok": "Cerințe îndeplinite",
        "checked_action": "Cerințe neîndeplinite",
        "checked_unknown": "Nu am putut verifica",
        "checked_unknown_note": (
            "Gri nu înseamnă în regulă. Sunt verificări la care nu am primit un "
            "răspuns, așa că nu putem spune nici că este bine, nici că este rău."
        ),
        "checked_not_applicable": "verificări nu se aplică acestui domeniu",
        "checked_withheld": "dintre acestea cer o autorizare pe care evaluarea pasivă nu o are",
        "evidence_result": "rezultat",
        "evidence_omitted": "alte date colectate, neafișate aici",
        "obs.observed": "măsurat",
        "obs.absent": "lipsește",
        "obs.inconclusive": "neconcludent",
        "obs.not_applicable": "nu se aplică",
        "value_true": "da",
        "value_false": "nu",
        "attr.candidate_count": "subdomenii descoperite",
        "attr.unreviewed_count": "dintre care încă neanalizate",
        "attr.low_confidence_count": "dintre care cu indiciu slab",
        "attr.present": "înregistrare publicată",
        "attr.valid": "sintaxă validă",
        "attr.issue_count": "autorități de certificare autorizate",
        "attr.has_unparsed": "conține intrări neinterpretabile",
        "attr.state": "stare",
        "attr.nameserver_count": "servere de nume",
        "attr.distinct_parent_count": "furnizori DNS distincți",
        "attr.resolves": "răspunde pentru orice subdomeniu",
        "attr.declared_selector_count": "selectoare declarate",
        "attr.present_selector_count": "selectoare găsite în DNS",
        "attr.any_selector_present": "cel puțin un selector publicat",
        "attr.all_selectors_present": "toate selectoarele publicate",
        "attr.policy": "politică",
        "attr.subdomain_policy": "politică pentru subdomenii",
        "attr.percentage": "procent din mesaje acoperit",
        "attr.external_authorization_required": (
            "rapoartele merg la alt domeniu, care trebuie să accepte"
        ),
        "attr.mode": "mod de aplicare",
        "attr.max_age_seconds": "valabilitatea politicii (secunde)",
        "attr.policy_invalid": "politica nu a putut fi interpretată",
        "attr.policy_fetch_reason": "de ce nu a putut fi descărcată politica",
        "attr.multiple_records": "mai multe înregistrări SPF publicate",
        "attr.dns_lookup_count": "interogări DNS necesare",
        "attr.exceeds_lookup_limit": "depășește limita de 10 interogări",
        "attr.permissive_all": "acceptă orice expeditor",
        "attr.soft_all": "eșec blând, mesajele trec oricum",
        "attr.http_reachable": "accesibil prin HTTP",
        "attr.https_reachable": "accesibil prin HTTPS",
        "attr.https_status_code": "cod de răspuns HTTPS",
        "attr.cookie_count": "cookie-uri primite",
        "attr.insecure_cookie_count": "dintre care fără atribute de siguranță",
        "attr.disclosing_headers": "antete care dezvăluie produsul folosit",
        "attr.version_disclosing_count": "dintre care dezvăluie și versiunea",
        "attr.redirects_to_https": "redirecționează către HTTPS",
        "attr.hsts_present": "HSTS publicat",
        "attr.hsts_max_age": "durata HSTS (secunde)",
        "attr.hsts_include_subdomains": "HSTS acoperă și subdomeniile",
        "attr.missing_baseline": "antete de securitate lipsă",
        "attr.missing_baseline_count": "câte lipsesc",
        "attr.hosts": "servere de mail",
        "attr.hosts_checked": "servere verificate",
        "attr.starttls_offered": "oferă conexiune criptată",
        "attr.starttls_everywhere": "toate oferă conexiune criptată",
        "attr.starttls_refused": "refuză conexiunea criptată",
        "attr.starttls_broken": "criptarea eșuează la conectare",
        "attr.certificate_valid_everywhere": "certificat valid pe toate",
        "attr.unreachable": "inaccesibile la momentul verificării",
        "attr.addresses": "adrese IP",
        "attr.countries": "țări",
        "attr.operators": "operatori de rețea",
        "attr.operator_count": "câți operatori",
        "attr.days_until_expiry": "zile până la expirarea certificatului",
        "attr.rdap.registration.days_until_expiry": (
            "zile până la expirarea înregistrării domeniului"
        ),
        "attr.delete_prohibited": "protejat împotriva ștergerii",
        "attr.transfer_prohibited": "protejat împotriva transferului",
        "attr.listed": "apare pe liste de reputație",
        "attr.contested": "sursele nu sunt de acord între ele",
        "attr.providers_consulted": "surse consultate",
        "attr.providers_listing": "surse care îl listează",
        "attr.providers_unavailable": "surse indisponibile la verificare",
        "attr.open_count": "porturi deschise",
        "attr.open_by_exposure": "dintre care, pe categorii",
        "attr.open_ports": "care porturi",
        "attr.probed_count": "porturi verificate",
        "attr.worst_exposure": "cel mai expus serviciu",
        "attr.expired": "expirat",
        "attr.not_yet_valid": "încă nevalabil",
        "attr.trusted": "emis de o autoritate de încredere",
        "attr.self_signed": "autosemnat",
        "attr.hostname_covered": "acoperă numele domeniului",
        "attr.weak_key": "cheie criptografică slabă",
        "attr.weak_signature": "semnătură criptografică slabă",
        "attr.supported": "versiuni TLS acceptate",
        "attr.deprecated_supported_count": "versiuni învechite încă acceptate",
        "attr.inconclusive_count": "versiuni pe care nu le-am putut testa",
        "attr.total_observation_count": "observații în total",
        "attr.stale_observation_count": "dintre care mai vechi decât fereastra",
        "val.dnssec_state.unsigned": "zona nu este semnată",
        "val.dnssec_state.signed_and_delegated": (
            "semnată, iar semnătura este publicată la registrar"
        ),
        "val.dnssec_state.signed_without_delegation": (
            "semnată, dar semnătura nu este publicată la registrar"
        ),
        "val.dnssec_state.unknown": "nu am putut determina",
        "val.mta_sts_mode.none": "publicată, dar inactivă",
        "val.mta_sts_mode.testing": "doar în test, nu blochează nimic",
        "val.mta_sts_mode.enforce": "se aplică",
        "val.dmarc_policy.none": "doar raportare, nu se ia nicio măsură",
        "val.dmarc_policy.quarantine": "mesajele nealiniate ajung în spam",
        "val.dmarc_policy.reject": "mesajele nealiniate sunt respinse",
        "val.exposure.remote_access": "acces la distanță",
        "val.exposure.database": "bază de date",
        "val.exposure.management": "administrare",
        "val.exposure.infrastructure": "infrastructură",
        "what_to_do": "Ce este de făcut",
        "caveat": "Înainte să schimbi ceva",
        "draft_guidance": (
            "Această recomandare este în lucru și nu a fost încă revizuită. "
            "Verific-o înainte de a acționa."
        ),
        "undetermined": "Verificări neconcludente",
        "undetermined_note": ("Nu am putut stabili aceste lucruri. Nu înseamnă că sunt în regulă."),
        "withheld": "Verificări neefectuate",
        "withheld_note": (
            "Acestea necesită o autorizare pe care această evaluare nu a avut-o. "
            "Nu au fost încercate."
        ),
        "evidence_erased": (
            "Dovezile pe baza cărora a fost calculat acest scor au fost șterse la "
            "{when}, conform politicii de păstrare a datelor. Scorul rămâne ca "
            "înregistrare a ceea ce s-a constatat atunci, dar nu mai poate fi recalculat."
        ),
        "methodology": "Metodologie",
        "mode": "Mod de observare",
        "notice": (
            "O evaluare externă de igienă, bazată pe observație publică și "
            "neintruzivă. Nu este o garanție de securitate, un audit, o certificare "
            "sau o determinare de conformitate NIS2."
        ),
        "severity.critical": "critic",
        "severity.high": "ridicat",
        "severity.medium": "mediu",
        "severity.low": "scăzut",
        "severity.informational": "informativ",
    },
    "en": {
        "confidential": "CONFIDENTIAL",
        "confidential_note": (
            "This report describes weaknesses in a public institution. Share it only "
            "with the people who need it in order to fix them."
        ),
        "title": "Cyber hygiene report",
        "organization": "Institution",
        "domain": "Domain",
        "generated": "Generated",
        "observed": "Observed",
        "score": "Score",
        "band": "Band",
        "band_withheld": (
            "No band is awarded: coverage is below the methodology's threshold. The "
            "score stands, but it rests on less evidence than a conclusion requires."
        ),
        "pillars": "By area",
        "no_pillar_score": "no score",
        "weight": "weight",
        "impact": "How exposed this institution is",
        "impact_none": "No weakness was identified in the checks that were performed.",
        "impact_lead": (
            "Each weakness below is a way somebody could reach this institution. "
            "Critical and high ones are fixed first."
        ),
        "scale_worst": "Critical",
        "scale_best": "Resilient",
        "score_of_100": "out of 100",
        "score_attribution": (
            "A score produced by this platform's external cyber hygiene methodology (version "
            "{methodology}), applied to publicly observable evidence. It is not a direct "
            "measurement of the institution's security."
        ),
        "coverage": "Checks completed",
        "coverage_meaning": (
            "{coverage}% of the methodology's applicable checks produced a result, weighted by "
            "how much each check counts. It does not describe how much of the institution's "
            "infrastructure was examined."
        ),
        "legend": "How to read the colours",
        "legend_direction": "100 is the best result, 0 the worst.",
        "importance": "importance",
        "of_the_score": "of the score",
        "how_scored_heading": "How the score was calculated",
        "how_scored": (
            "Each check takes a factor — met 1, partly 0.5, unmet 0 — and the areas above combine "
            "according to the weights shown. Inconclusive checks do not lower the score; they "
            "only reduce the percentage of checks completed."
        ),
        "cap_heading": "Why the score was capped",
        "cap_explained": (
            "The methodology caps the score at {ceiling} out of 100 when this is observed with "
            "high confidence. Without the cap the score would have been {uncapped}."
        ),
        "importance_high": "high",
        "importance_medium": "medium",
        "importance_low": "low",
        "no_pillar_score_why": "no reputation provider is configured",
        "no_pillar_score_generic": "no conclusive checks in this area",
        "band.resilient": "Resilient",
        "band.managed": "Managed",
        "band.developing": "Developing",
        "band.exposed": "Exposed",
        "band.critical": "Critical",
        "pillar.dns": "DNS",
        "pillar.email": "E-mail",
        "pillar.web_tls": "Web and TLS",
        "pillar.attack_surface": "Attack surface",
        "pillar.reputation": "Reputation",
        "pillar.exposure_hygiene": "Exposure hygiene",
        "findings": "What needs fixing",
        "no_findings": "No weakness was identified in the checks that were performed.",
        "requirement_unmet": "Requirement not met",
        "affects": "Concerns",
        "why": "Why it matters",
        "evidence_heading": "What we observed",
        "checked_heading": "What we checked",
        "assets_heading": "Names discovered publicly",
        "assets_note": (
            "Found in public sources (certificate logs, DNS). Not confirmed assets: the "
            "organization decides what belongs to it. The index shows how strong the link to the "
            "assessed domain is."
        ),
        "asset_confidence": "index",
        "asset_rest": "Show the remaining names",
        "asset_shared": "on shared hosting",
        "basis.authorized_domain": "the authorized domain itself",
        "basis.subdomain_of_authorized_domain": "subdomain of the authorized domain",
        "basis.unrelated_name": "name with no demonstrated link",
        "basis.shared_address": "same IP address",
        "insights_heading": "Automated reading of the evidence",
        "insight.measured": "measured",
        "insight.inferred": "inferred",
        "insight.recommended": "recommendation",
        "insights_evidence": "See the evidence",
        "checked_ok": "Requirements met",
        "checked_action": "Requirements not met",
        "checked_unknown": "Could not check",
        "checked_unknown_note": (
            "Grey does not mean fine. These are checks we got no answer for, so we "
            "can say neither that it is good nor that it is bad."
        ),
        "checked_not_applicable": "checks do not apply to this domain",
        "checked_withheld": "of those need an authorization a passive assessment does not have",
        "evidence_result": "result",
        "evidence_omitted": "further data collected, not shown here",
        "obs.observed": "measured",
        "obs.absent": "not present",
        "obs.inconclusive": "inconclusive",
        "obs.not_applicable": "not applicable",
        "value_true": "yes",
        "value_false": "no",
        "attr.candidate_count": "subdomains discovered",
        "attr.unreviewed_count": "of which not yet reviewed",
        "attr.low_confidence_count": "of which low-confidence",
        "attr.present": "record published",
        "attr.valid": "syntax valid",
        "attr.issue_count": "certificate authorities authorised",
        "attr.has_unparsed": "contains entries we could not read",
        "attr.state": "state",
        "attr.nameserver_count": "name servers",
        "attr.distinct_parent_count": "distinct DNS providers",
        "attr.resolves": "answers for any subdomain",
        "attr.declared_selector_count": "selectors declared",
        "attr.present_selector_count": "selectors found in DNS",
        "attr.any_selector_present": "at least one selector published",
        "attr.all_selectors_present": "all selectors published",
        "attr.policy": "policy",
        "attr.subdomain_policy": "policy for subdomains",
        "attr.percentage": "percentage of messages covered",
        "attr.external_authorization_required": (
            "reports go to another domain, which must authorise it"
        ),
        "attr.mode": "enforcement mode",
        "attr.max_age_seconds": "policy lifetime (seconds)",
        "attr.policy_invalid": "policy could not be read",
        "attr.policy_fetch_reason": "why the policy could not be fetched",
        "attr.multiple_records": "more than one SPF record published",
        "attr.dns_lookup_count": "DNS lookups required",
        "attr.exceeds_lookup_limit": "exceeds the limit of 10 lookups",
        "attr.permissive_all": "accepts any sender",
        "attr.soft_all": "soft fail, messages pass anyway",
        "attr.http_reachable": "reachable over HTTP",
        "attr.https_reachable": "reachable over HTTPS",
        "attr.https_status_code": "HTTPS response code",
        "attr.cookie_count": "cookies received",
        "attr.insecure_cookie_count": "of which missing safety attributes",
        "attr.disclosing_headers": "headers disclosing the product in use",
        "attr.version_disclosing_count": "of which also disclose a version",
        "attr.redirects_to_https": "redirects to HTTPS",
        "attr.hsts_present": "HSTS published",
        "attr.hsts_max_age": "HSTS lifetime (seconds)",
        "attr.hsts_include_subdomains": "HSTS covers subdomains too",
        "attr.missing_baseline": "security headers missing",
        "attr.missing_baseline_count": "how many are missing",
        "attr.hosts": "mail servers",
        "attr.hosts_checked": "servers checked",
        "attr.starttls_offered": "offer an encrypted connection",
        "attr.starttls_everywhere": "all offer an encrypted connection",
        "attr.starttls_refused": "refuse an encrypted connection",
        "attr.starttls_broken": "encryption fails on connect",
        "attr.certificate_valid_everywhere": "certificate valid on all of them",
        "attr.unreachable": "unreachable when we checked",
        "attr.addresses": "IP addresses",
        "attr.countries": "countries",
        "attr.operators": "network operators",
        "attr.operator_count": "how many operators",
        "attr.days_until_expiry": "days until the certificate expires",
        "attr.rdap.registration.days_until_expiry": "days until the domain registration expires",
        "attr.delete_prohibited": "protected against deletion",
        "attr.transfer_prohibited": "protected against transfer",
        "attr.listed": "appears on reputation lists",
        "attr.contested": "the sources disagree with each other",
        "attr.providers_consulted": "sources consulted",
        "attr.providers_listing": "sources listing it",
        "attr.providers_unavailable": "sources unavailable when we checked",
        "attr.open_count": "open ports",
        "attr.open_by_exposure": "of which, by category",
        "attr.open_ports": "which ports",
        "attr.probed_count": "ports checked",
        "attr.worst_exposure": "most exposed service",
        "attr.expired": "expired",
        "attr.not_yet_valid": "not valid yet",
        "attr.trusted": "issued by a trusted authority",
        "attr.self_signed": "self-signed",
        "attr.hostname_covered": "covers the domain name",
        "attr.weak_key": "weak cryptographic key",
        "attr.weak_signature": "weak cryptographic signature",
        "attr.supported": "TLS versions supported",
        "attr.deprecated_supported_count": "outdated versions still supported",
        "attr.inconclusive_count": "versions we could not test",
        "attr.total_observation_count": "observations in total",
        "attr.stale_observation_count": "of which older than the window",
        "val.dnssec_state.unsigned": "the zone is not signed",
        "val.dnssec_state.signed_and_delegated": (
            "signed, and the signature is published at the registrar"
        ),
        "val.dnssec_state.signed_without_delegation": (
            "signed, but the signature is not published at the registrar"
        ),
        "val.dnssec_state.unknown": "we could not determine it",
        "val.mta_sts_mode.none": "published but inactive",
        "val.mta_sts_mode.testing": "testing only, blocks nothing",
        "val.mta_sts_mode.enforce": "enforced",
        "val.dmarc_policy.none": "reporting only, no action taken",
        "val.dmarc_policy.quarantine": "unaligned messages go to spam",
        "val.dmarc_policy.reject": "unaligned messages are rejected",
        "val.exposure.remote_access": "remote access",
        "val.exposure.database": "database",
        "val.exposure.management": "management",
        "val.exposure.infrastructure": "infrastructure",
        "what_to_do": "What to do",
        "caveat": "Before you change anything",
        "draft_guidance": (
            "This guidance is a draft and has not yet been reviewed. Check it before acting on it."
        ),
        "undetermined": "Inconclusive checks",
        "undetermined_note": ("We could not establish these. That does not mean they are fine."),
        "withheld": "Checks not performed",
        "withheld_note": (
            "These require an authorization this assessment did not hold. They were not attempted."
        ),
        "evidence_erased": (
            "The evidence this score was computed from was removed on {when} under the "
            "data retention policy. The score stands as a record of what was found at "
            "the time, but it can no longer be recomputed."
        ),
        "methodology": "Methodology",
        "mode": "Observation mode",
        "notice": (
            "An external hygiene assessment based on public, non-intrusive "
            "observation. Not a security guarantee, audit, certification, or NIS2 "
            "conformity determination."
        ),
        "severity.critical": "critical",
        "severity.high": "high",
        "severity.medium": "medium",
        "severity.low": "low",
        "severity.informational": "informational",
    },
}

#: Inline, because a linked stylesheet is a network request and this file has to render
#: identically from a downloads folder with no connectivity.
_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 0 0 3rem; font: 15px/1.55 "Segoe UI", system-ui, sans-serif;
       color: #16202b; background: #fff; }
.sheet { max-width: 48rem; margin: 0 auto; padding: 0 1.5rem; }
.confidential { background: #7a1420; color: #fff; padding: 0.5rem 1.5rem;
                font-weight: 700; letter-spacing: 0.08em; }
.confidential p { margin: 0.35rem 0 0; font-weight: 400; letter-spacing: 0;
                  font-size: 0.85rem; }
h1 { font-size: 1.6rem; margin: 1.6rem 0 0.25rem; }
h2 { font-size: 1.15rem; margin: 2rem 0 0.6rem; border-bottom: 1px solid #d7dee6;
     padding-bottom: 0.3rem; }
h3 { font-size: 1rem; margin: 0 0 0.3rem; }
dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem;
           margin: 0.8rem 0 0; }
dl.facts dt { color: #5a6673; }
dl.facts dd { margin: 0; }
.headline { display: flex; gap: 2rem; align-items: baseline; margin: 1.2rem 0 0; }
.headline .value { font-size: 2.4rem; font-weight: 700; }
.note { background: #f3f6f9; border-left: 3px solid #8a99a8; padding: 0.6rem 0.9rem;
        margin: 0.8rem 0; }
.caveat { background: #fdf4e7; border-left: 3px solid #b8791f; padding: 0.6rem 0.9rem;
          margin: 0.6rem 0; }
.draft { background: #fdf4e7; border-left: 3px solid #b8791f; padding: 0.4rem 0.9rem;
         margin: 0.6rem 0; font-size: 0.85rem; }
.finding { border: 1px solid #d7dee6; border-radius: 6px; padding: 0.9rem 1.1rem;
           margin: 0.8rem 0; page-break-inside: avoid; }
.severity { display: inline-block; font-size: 0.72rem; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.06em; padding: 0.1rem 0.5rem;
            border-radius: 999px; border: 1px solid currentColor; }
.severity-critical, .severity-high { color: #7a1420; }
.severity-medium { color: #8a5a12; }
.severity-low, .severity-informational { color: #4a5560; }
.muted { color: #5a6673; }
.unmet { margin: 0.5rem 0 0.1rem; font-size: 0.78rem; font-weight: 700;
         letter-spacing: 0.04em; text-transform: uppercase; color: #7a1420; }
.subject { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
           font-size: 0.9rem; }
table.pillars { width: 100%; border-collapse: collapse; margin-top: 0.6rem; }
table.pillars th, table.pillars td { text-align: left; padding: 0.4rem 0.5rem;
                                     border-bottom: 1px solid #e6ebf0;
                                     vertical-align: middle; }
table.pillars td.number { text-align: right; font-variant-numeric: tabular-nums;
                          font-weight: 700; width: 3.4rem; }
table.pillars td.name { width: 11rem; }
table.pillars td.importance { width: 7rem; font-size: 0.8rem; color: #5a6673; }

/* Bars are a filled div inside a track, not a chart library and not an image.
   WeasyPrint runs no JavaScript and this report embeds nothing, so a percentage
   width is the whole mechanism -- it renders identically in a browser and in the
   PDF, and it degrades to a readable number if styles are stripped entirely. */
.track { background: #e9eef3; border-radius: 3px; height: 0.62rem; width: 100%; }
.fill { height: 0.62rem; border-radius: 3px; }
.fill-resilient { background: #1d7a4c; }
.fill-managed { background: #4a9e3f; }
.fill-developing { background: #c08a1e; }
.fill-exposed { background: #c2601c; }
.fill-critical { background: #a3202f; }
.fill-none { background: #c8d2db; }

.headline { margin: 1.1rem 0 0.4rem; }
.headline .value { font-size: 3rem; font-weight: 800; line-height: 1;
                   font-variant-numeric: tabular-nums; }
.headline .of { font-size: 0.95rem; color: #5a6673; margin-left: 0.35rem; }
.headline .bandname { font-size: 1.5rem; font-weight: 700; margin-left: 1.2rem; }
.scale { margin-top: 0.7rem; }
.scale .ends { font-size: 0.75rem; color: #5a6673; margin-top: 0.2rem; }
.scale .ends .right { float: right; }

/* One chip per severity, carrying its own count. Colour is never the only signal:
   the number and the word are both present, which is what keeps this readable in
   greyscale and to a screen reader. */
.impact { margin-top: 0.5rem; }
.chip { display: inline-block; border: 1px solid currentColor; border-radius: 6px;
        padding: 0.3rem 0.7rem; margin: 0 0.4rem 0.4rem 0; font-size: 0.85rem; }
.chip .count { font-weight: 800; font-size: 1.15rem; margin-right: 0.35rem;
               font-variant-numeric: tabular-nums; }
.chip-critical, .chip-high { color: #7a1420; }
.chip-medium { color: #8a5a12; }
.chip-low, .chip-informational { color: #4a5560; }
.lead { color: #3d4854; margin: 0.5rem 0 0; }

table.evidence { border-collapse: collapse; margin: 0.3rem 0 0.6rem; font-size: 0.86rem; }
table.evidence td { padding: 0.22rem 0.7rem 0.22rem 0; vertical-align: top;
                    border-bottom: 1px solid #eef2f6; }
/* Prose, not monospace. These were collector keys when the column was written; they are
   now sentences, and a proportional label beside a monospace value is what tells the
   reader which half is ours and which half is their infrastructure's. */
table.evidence td.ename { color: #5a6673; font-size: 0.82rem; padding-right: 1.1rem;
                          max-width: 16rem; }
.obs-status { font-weight: 700; }

table.checked { width: 100%; border-collapse: collapse; margin: 0.4rem 0 0.5rem;
                table-layout: fixed; }
table.checked td { vertical-align: top; padding: 0 0.9rem 0 0; }
table.checked h3 { font-size: 0.84rem; margin: 0 0 0.4rem; letter-spacing: 0.02em; }
table.checked ul { margin: 0; padding: 0; list-style: none; }
table.checked li { font-size: 0.78rem; line-height: 1.35; margin-bottom: 0.25rem;
                   color: #3d4854; }
.col-ok h3 { color: #1d7a4c; }
.col-action h3 { color: #a3202f; }
.col-unknown h3 { color: #5a6673; }
.dot { display: inline-block; width: 0.5rem; height: 0.5rem; border-radius: 50%;
       margin-right: 0.4rem; }
.dot-ok { background: #1d7a4c; }
.dot-fail { background: #a3202f; }
.dot-warning { background: #c08a1e; }
.dot-unknown { background: #9aa5b1; }
.checked-note { font-size: 0.76rem; color: #5a6673; margin: 0.1rem 0 0.3rem; }
.checked-na { font-size: 0.76rem; color: #7a8592; margin: 0.2rem 0 0; }
code.check-id { font-size: 0.72rem; color: #8a939c; }

h3.asset-basis { font-size: 0.82rem; margin: 0.7rem 0 0.25rem; color: #3d4854; }
ul.assets { margin: 0; padding-left: 1.1rem; font-size: 0.8rem; line-height: 1.5;
            column-count: 2; column-gap: 1.6rem; }
ul.assets li { break-inside: avoid; }
details.asset-rest > summary { cursor: pointer; color: #3d5a80; font-size: 0.76rem;
                               list-style: none; margin: 0.15rem 0 0.2rem; }
details.asset-rest > summary::-webkit-details-marker { display: none; }
details.asset-rest > summary::before { content: "▸  "; }
details.asset-rest[open] > summary::before { content: "▾  "; }

/* Visibly a different voice from the reviewed findings above it. Softer rule, indented
   block, no severity colours -- a reader should be able to tell at a glance that this
   part was written by a machine without having to read the caption first. */
.insights { border-left: 3px solid #c9d3dd; padding: 0.1rem 0 0.1rem 0.9rem;
            margin: 0.3rem 0 0.6rem; }
.insights .note { font-size: 0.78rem; color: #5a6673; margin: 0 0 0.55rem; }
.insight { margin: 0 0 0.5rem; font-size: 0.86rem; line-height: 1.45; color: #2b3440; }
.insight-kind { display: inline-block; font-size: 0.7rem; font-weight: 700;
                letter-spacing: 0.04em; text-transform: uppercase; color: #5a6673;
                border: 1px solid #d7dee6; border-radius: 3px; padding: 0 0.3rem;
                margin-right: 0.45rem; vertical-align: 0.05rem; }
.insight-evidence { margin: -0.2rem 0 0.7rem 0.2rem; font-size: 0.8rem; }
.insight-evidence > summary { cursor: pointer; color: #3d5a80; font-size: 0.76rem;
                              list-style: none; }
.insight-evidence > summary::-webkit-details-marker { display: none; }
.insight-evidence > summary::before { content: "▸  "; }
.insight-evidence[open] > summary::before { content: "▾  "; }
.insight-evidence table.evidence { margin-left: 0.9rem; }
td.ename.indented { padding-left: 0.9rem; }

/* On paper there is nothing to click, so everything is open. A folded section in a PDF
   is evidence the reader cannot reach at all. */
@media print {
  .insight-evidence > summary, .asset-rest > summary { display: none; }
  .insight-evidence > table { display: table !important; }
  .asset-rest > ul { display: block !important; }
}

.legend { margin: 0.5rem 0 0.2rem; font-size: 0.78rem; color: #5a6673; }
.legend-title { font-weight: 700; }
.legend .keys { margin-top: 0.3rem; }
.legend .key { display: inline-block; margin: 0 0.9rem 0.25rem 0; white-space: nowrap; }
.swatch { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 2px;
          margin-right: 0.3rem; vertical-align: -0.05rem; }
footer { margin-top: 2.5rem; padding-top: 0.8rem; border-top: 1px solid #d7dee6;
         font-size: 0.82rem; color: #5a6673; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 0.85em;
       word-break: break-all; }
@media print { .confidential { position: fixed; top: 0; left: 0; right: 0; }
               .sheet { padding-top: 4.5rem; } }
"""


def _text(locale: str, key: str) -> str:
    return _TEXT[locale][key]


def _pick(locale: str, romanian: str, english: str) -> str:
    return romanian if locale == "ro" else english


def _stamp(moment: datetime) -> str:
    """A fixed, unambiguous rendering.

    Not the reader's locale format: a report is forwarded, and "03/08/2026" means two
    different days depending on who opens it.
    """
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def render_report(report: ReportDocument, locale: str = DEFAULT_LOCALE) -> str:
    if locale not in _TEXT:
        raise ValueError(f"unsupported report locale: {locale}")

    return document(
        element(
            "head",
            element("meta", charset="utf-8"),
            element("meta", name="viewport", content="width=device-width, initial-scale=1"),
            # No indexing, and no referrer if a link is ever followed out of the page.
            element("meta", name="robots", content="noindex, nofollow, noarchive"),
            element("meta", name="referrer", content="no-referrer"),
            element("title", f"{_text(locale, 'title')} — {report.domain}"),
            element("style", Raw(_STYLE)),
        ),
        element(
            "body",
            _confidential(locale),
            element(
                "div",
                _header(report, locale),
                _headline(report, locale),
                # Before the areas, because it answers the question people open the
                # report with. A pillar score of 25 does not tell somebody whether to
                # worry this week; "two critical, four high" does.
                _impact(report, locale),
                _pillars(report, locale),
                _how_scored(report, locale),
                _checked(report, locale),
                _findings(report, locale),
                _insights(report, locale),
                _assets(report, locale),
                _not_determined(report, locale),
                _footer(report, locale),
                class_="sheet",
            ),
        ),
        lang=locale,
    )


def _confidential(locale: str) -> Element:
    return element(
        "div",
        element("div", _text(locale, "confidential")),
        element("p", _text(locale, "confidential_note")),
        class_="confidential",
    )


def _header(report: ReportDocument, locale: str) -> Element:
    return element(
        "header",
        element("h1", _text(locale, "title")),
        element(
            "dl",
            element("dt", _text(locale, "organization")),
            element("dd", report.organization_name),
            element("dt", _text(locale, "domain")),
            element("dd", element("span", report.domain, class_="subject")),
            element("dt", _text(locale, "observed")),
            element("dd", _stamp(report.observed_at)),
            element("dt", _text(locale, "generated")),
            element("dd", _stamp(report.generated_at)),
            class_="facts",
        ),
    )


#: Where each band starts, worst first. Mirrors `bands` in the methodology, and
#: `test_report_band_labels_match_the_methodology` fails if the two drift -- the labels
#: exist in the catalogue and a report that prints `developing` to a Romanian reader is
#: not using them.
_BAND_FLOORS: tuple[tuple[str, float], ...] = (
    ("critical", 0.0),
    ("exposed", 30.0),
    ("developing", 55.0),
    ("managed", 75.0),
    ("resilient", 90.0),
)

#: Weight above which an area is called out as carrying more of the score. Read from
#: the pillar's own weight rather than hardcoded per area, so re-weighting the
#: methodology moves the wording with it.
_IMPORTANCE_HIGH = 0.2
_IMPORTANCE_MEDIUM = 0.13


def _band_for(score: float | None) -> str:
    """The band a score falls in, for colouring only.

    Not for awarding one: whether a band is *awarded* depends on coverage and is decided
    by the scorer, not here. This colours a bar, and a bar with no colour rule would be
    decoration.
    """
    if score is None:
        return "none"
    band = "critical"
    for name, floor in _BAND_FLOORS:
        if score >= floor:
            band = name
    return band


def _band_label(locale: str, band: str) -> str:
    return _TEXT[locale].get(f"band.{band}", band)


def _pillar_label(locale: str, pillar: str) -> str:
    """The area's name in the reader's language, falling back to the identifier.

    The fallback is deliberate and visible: an area added to the methodology and not
    translated shows up as `exposure_hygiene` in the report, which is ugly enough that
    somebody fixes it. Silently omitting the row would hide a whole area of the score.
    """
    return _TEXT[locale].get(f"pillar.{pillar}", pillar)


def _importance(locale: str, weight: float) -> str:
    if weight >= _IMPORTANCE_HIGH:
        return _text(locale, "importance_high")
    if weight >= _IMPORTANCE_MEDIUM:
        return _text(locale, "importance_medium")
    return _text(locale, "importance_low")


#: The narrowest a bar may render while still being a bar.
#:
#: A score of zero is a *result*: every check in that area failed. Drawn at its true
#: width it is an empty track, which on the page is indistinguishable from the area that
#: has no score at all -- so the worst possible outcome looked like a missing one. E-mail
#: scoring 0 on a real report is what made that visible.
#:
#: The sliver is deliberately too small to misread as a quantity. It says "measured, and
#: it is the bottom", and the number beside it says the rest.
_MINIMUM_VISIBLE_WIDTH = 1.5


def _bar(percent: float, band: str) -> Node:
    """A filled track.

    Clamped at both ends: above, because a bar wider than its track is a layout bug that
    reads as a better result; below, because zero drawn as nothing reads as no result at
    all.
    """
    width = max(0.0, min(100.0, percent))
    if width < _MINIMUM_VISIBLE_WIDTH:
        width = _MINIMUM_VISIBLE_WIDTH
    return element(
        "div",
        element("div", "", class_=f"fill fill-{band}", style=f"width: {width:g}%"),
        class_="track",
    )


def _legend(locale: str) -> Node:
    """What the colours mean, beside the bars that use them.

    Added because a reader looking at a coloured bar and a number has no way to know
    which direction is good. The bands and their boundaries come from `_BAND_FLOORS`, so
    a methodology that re-cuts them moves the legend with it rather than leaving a
    caption that describes the previous scale.
    """
    swatches: list[Node] = []
    for index, (band, floor) in enumerate(_BAND_FLOORS):
        ceiling = 100.0 if index + 1 == len(_BAND_FLOORS) else _BAND_FLOORS[index + 1][1] - 1.0
        swatches.append(
            element(
                "span",
                element("span", "", class_=f"swatch fill-{band}"),
                f"{_band_label(locale, band)} {floor:g}\u2013{ceiling:g}",
                class_="key",
            )
        )
    return element(
        "div",
        element(
            "span",
            f"{_text(locale, 'legend')} \u2014 {_text(locale, 'legend_direction')}",
            class_="legend-title",
        ),
        element("div", *swatches, class_="keys"),
        class_="legend",
    )


def _impact(report: ReportDocument, locale: str) -> Node:
    """How exposed the institution is, in the one form every reader understands: how
    many, and how bad.

    Placed before the areas because it answers the question people actually open the
    report with. A pillar score of 25 does not tell somebody whether to worry this week;
    two critical findings does.
    """
    counts: dict[str, int] = {}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    if not counts:
        return element(
            "section",
            element("h2", _text(locale, "impact")),
            element("p", _text(locale, "impact_none")),
        )

    chips = [
        element(
            "span",
            element("span", str(counts[severity]), class_="count"),
            _text(locale, f"severity.{severity}"),
            class_=f"chip chip-{severity}",
        )
        for severity in SEVERITY_ORDER
        if counts.get(severity)
    ]
    return element(
        "section",
        element("h2", _text(locale, "impact")),
        element("div", *chips, class_="impact"),
        element("p", _text(locale, "impact_lead"), class_="lead"),
    )


def _headline(report: ReportDocument, locale: str) -> Element:
    children: list[Node] = [
        element(
            "div",
            element("div", _text(locale, "score"), class_="muted"),
            element("div", "—" if report.score is None else f"{report.score:g}", class_="value"),
        ),
        element(
            "div",
            element("div", _text(locale, "coverage"), class_="muted"),
            element("div", f"{report.coverage_percentage:g}%", class_="value"),
        ),
    ]
    # The band is shown only where the methodology awards one. Below the coverage floor
    # the number stands and the band does not, so the report must not print a band-shaped
    # blank that a reader fills in themselves.
    if report.coverage_sufficient and report.band:
        children.insert(
            1,
            element(
                "div",
                element("div", _text(locale, "band"), class_="muted"),
                # The methodology carries `label_ro` and `label_en` for every band and
                # this printed the raw identifier, so a Romanian institution read
                # "developing" in an otherwise Romanian document.
                element("div", _band_label(locale, report.band), class_="value"),
            ),
        )

    blocks: list[Node] = [element("div", *children, class_="headline")]

    # Where the score sits on the whole scale, with both ends named. A number alone
    # leaves the reader to guess whether 55.6 is nearly good or nearly bad.
    if report.score is not None:
        blocks.append(
            element(
                "div",
                _bar(report.score, _band_for(report.score)),
                element(
                    "div",
                    element("span", _text(locale, "scale_worst")),
                    element("span", _text(locale, "scale_best"), class_="right"),
                    class_="ends",
                ),
                class_="scale",
            )
        )

    # Where the number came from, beside the number. The score is an output of this
    # platform's methodology applied to what could be observed from outside; printed
    # alone it reads as a measurement of the institution, which it is not. The same
    # reasoning behind the existing "not an audit, not a certification" notice, moved to
    # where the figure actually is rather than left in the footer.
    blocks.append(
        element(
            "p",
            _text(locale, "score_attribution").replace("{methodology}", report.methodology_version),
            class_="lead",
        )
    )

    # And what the coverage figure counts, worded from the computation rather than around
    # it. It is a weighted share of the methodology's applicable checks that reached a
    # result -- not a proportion of the institution's infrastructure, which is what
    # "coverage" on its own invites a reader to assume.
    blocks.append(
        element(
            "p",
            _text(locale, "coverage_meaning").replace(
                "{coverage}", f"{report.coverage_percentage:g}"
            ),
            class_="lead",
        )
    )
    if not report.coverage_sufficient:
        blocks.append(element("p", _text(locale, "band_withheld"), class_="note"))
    if report.evidence_erased_at is not None:
        # Said beside the score rather than in the footer with the digests. A reader who
        # takes the number and stops reading should still have been told that the
        # workings behind it no longer exist.
        blocks.append(
            element(
                "p",
                _text(locale, "evidence_erased").replace(
                    "{when}", _stamp(report.evidence_erased_at)
                ),
                class_="caveat",
            )
        )
    for warning in report.warnings:
        blocks.append(element("p", warning, class_="note"))
    return element("section", *blocks)


def _pillars(report: ReportDocument, locale: str) -> Node:
    """Each area as a bar, named in the reader's language.

    The previous version printed the identifier and the raw weight -- `attack_surface`
    and `0.15` -- which are the two facts in the whole report that mean nothing to the
    person receiving it. The weight is a methodology parameter; what a reader needs is
    whether this area matters more than the next one.

    An area with no score keeps its row and says why. Dropping it would leave a report
    that silently covers five areas out of six, and a reader counting rows would have no
    way to know.
    """
    if not report.pillars:
        return element("div")

    rows = []
    for pillar in report.pillars:
        if pillar.score is None:
            reason = (
                _text(locale, "no_pillar_score_why")
                if pillar.pillar == "reputation"
                else _text(locale, "no_pillar_score_generic")
            )
            measure: Node = element(
                "span", f"{_text(locale, 'no_pillar_score')} — {reason}", class_="muted"
            )
            number: Node = element("span", "—", class_="muted")
        else:
            measure = _bar(pillar.score, _band_for(pillar.score))
            number = f"{pillar.score:g}"

        rows.append(
            element(
                "tr",
                element("td", _pillar_label(locale, pillar.pillar), class_="name"),
                element("td", measure),
                element("td", number, class_="number"),
                element(
                    "td",
                    # The word and the number. An earlier version printed `0.15`, which
                    # is a methodology parameter and means nothing to the reader; it was
                    # replaced by "high importance", which means something but cannot be
                    # checked. As a share of the score it is both -- the actual weight,
                    # in the only unit a reader can act on when deciding what to fix.
                    f"{_text(locale, 'importance')} {_importance(locale, pillar.weight)}"
                    f" · {pillar.weight * 100:g}% {_text(locale, 'of_the_score')}",
                    class_="importance",
                ),
            )
        )

    return element(
        "section",
        element("h2", _text(locale, "pillars")),
        _legend(locale),
        element("table", *rows, class_="pillars"),
    )


#: Attributes whose values come from a fixed vocabulary rather than being a number, a
#: flag or free text. The value-set name is shared where the vocabulary is: a DMARC
#: policy and a DMARC subdomain policy are the same three words, and translating them
#: twice is how the two drift apart.
_VALUE_SETS = {
    "state": "dnssec_state",
    "mode": "mta_sts_mode",
    "policy": "dmarc_policy",
    "subdomain_policy": "dmarc_policy",
    "worst_exposure": "exposure",
    "open_by_exposure": "exposure",
}


def _attribute_label(locale: str, observation_type: str | None, name: str) -> str:
    """The reader's name for a collector attribute, or the collector's own.

    `distinct_parent_count` is precise and means nothing to the person who has to act on
    it. These are the same facts under names somebody without a security team can read.

    The fall-back to the raw name is the important part. A collector that starts
    reporting something new gets its attribute shown untranslated rather than dropped:
    an ugly row is a fixable oversight, a missing one is the report quietly saying less
    than it knows. A test asserts that fall-back rather than trusting it.

    Most names mean one thing everywhere, so most are labelled once. `days_until_expiry`
    is not: on a certificate it is weeks of warning, on a domain registration it is the
    domain itself, and telling a mayor the wrong one is worse than telling them neither.
    Those get a label per observation type.
    """
    table = _TEXT[locale]
    if observation_type:
        specific = table.get(f"attr.{observation_type}.{name}")
        if specific is not None:
            return specific
    return table.get(f"attr.{name}", name)


def _attribute_value(locale: str, name: str, value: str) -> str:
    """One evidence value as the reader sees it.

    `p=none` is not a policy an institution can weigh; "reporting only, no action taken"
    is the same fact and answers the question the reader actually has, which is whether
    anything is currently being stopped.

    Every value here originated outside this system -- a policy file, a DNS record, a
    mail server banner -- and is used only as a dictionary key, never as a format string
    or a lookup that could be made to match something it should not. An unknown value
    falls through and is shown as it arrived, escaped on serialization like all the rest.
    """
    if value == "true":
        return _text(locale, "value_true")
    if value == "false":
        return _text(locale, "value_false")
    value_set = _VALUE_SETS.get(name)
    if value_set is None:
        return value
    table = _TEXT[locale]
    whole = table.get(f"val.{value_set}.{value}")
    if whole is not None:
        return whole
    # A breakdown arrives as `name:count` pairs, so the vocabulary applies to each name
    # rather than to the whole string. Anything that is not that shape falls through
    # untouched -- including a value we simply do not have a word for yet.
    if ":" not in value:
        return value
    translated = []
    for pair in value.split(", "):
        key, separator, count = pair.partition(":")
        if not separator:
            return value
        translated.append(f"{table.get(f'val.{value_set}.{key}', key)}: {count}")
    return ", ".join(translated)


def _evidence(finding: ReportFinding, locale: str) -> list[Node]:
    """What the collectors saw, beside what the report says to change.

    Added because the report told an institution what to fix and never showed what was
    found. "Publish DMARC" is an instruction; "no DMARC record was returned for this
    domain" is the reason, and a public body being asked to change its DNS is entitled to
    the second before it acts on the first.

    The status is shown even when there are no attributes, because `absent` and
    `inconclusive` are the whole content in that case: we looked and it was not there, or
    we could not look. A reader acts differently on each.

    Values pass through the element tree like every other string here, so a header or a
    mail server banner containing markup is escaped on serialization rather than by
    anything in this function remembering to.
    """
    if finding.evidence_status is None:
        return []
    if finding.evidence_status == "absent" and not finding.evidence:
        # Nothing to show but the word "missing", under a heading that promises what we
        # observed and beside a title that already says the record is not published. A
        # box that restates the verdict teaches a reader to skip the box, including on
        # the findings where it carries the whole answer.
        #
        # `inconclusive` deliberately does not qualify: "we could not check this" is not
        # implied by anything else on the page, and hiding it would let a gap in our own
        # measurement read as a fact about the institution.
        return []

    rows = [
        element(
            "tr",
            element("td", _text(locale, "evidence_result"), class_="ename"),
            element(
                "td",
                _TEXT[locale].get(f"obs.{finding.evidence_status}", finding.evidence_status),
                class_="obs-status",
            ),
        )
    ]
    rows += [
        element(
            "tr",
            element(
                "td",
                _attribute_label(locale, finding.evidence_type, name),
                class_="ename",
            ),
            element("td", _attribute_value(locale, name, value)),
        )
        for name, value in finding.evidence
    ]
    if finding.evidence_omitted:
        rows.append(
            element(
                "tr",
                element(
                    "td",
                    _text(locale, "evidence_omitted"),
                    class_="ename",
                ),
                element("td", str(finding.evidence_omitted)),
            )
        )
    return [
        element("p", element("strong", _text(locale, "evidence_heading"))),
        element("table", *rows, class_="evidence"),
    ]


#: Which column each recorded outcome belongs in.
#:
#: `unknown` gets its own column rather than being folded into either neighbour, and that
#: is the whole point of the section. A check we could not run is not a check that passed,
#: and putting it on the green side would turn "we never reached the site over HTTPS" into
#: a reassurance. Putting it on the red side would be its own lie, inventing a weakness
#: out of a measurement we do not have.
#: Reading order within a column. Only the action column has more than one outcome in
#: it, so only its two matter; everything else shares a rank and keeps the order it came
#: in with.
_ACTION_ORDER = {"fail": -1}

_CHECK_COLUMNS = {
    "pass": "ok",
    "fail": "action",
    "warning": "action",
    "unknown": "unknown",
}


def _checked(report: ReportDocument, locale: str) -> Node:
    """What was examined, in three columns, before what has to be done about it.

    The report used to list only failures. Five checks passing and four returning nothing
    were both rendered as silence, and silence reads as "fine" -- so an institution could
    read a page with eight problems on it and reasonably conclude everything else had been
    tested and was healthy. Half of it had not been tested at all.

    Not-applicable checks are counted rather than listed. They are genuinely uninteresting
    -- a port-exposure check on a passive run, a reputation check with no provider
    configured -- and nine more lines of them would push the three columns that matter off
    the first page. The count stays so the arithmetic still adds up to the whole
    methodology, which is what lets a reader tell this is a summary and not a selection.
    """
    if not report.checks:
        return element("section")

    columns: dict[str, list[Node]] = {"ok": [], "action": [], "unknown": []}
    not_applicable = 0
    # Failures before warnings, so the column that asks for action opens with the thing
    # that most needs it. Sorted here rather than upstream because it is a reading order,
    # not a fact about the checks: the list arrives by identifier, which groups by pillar
    # and puts whichever pillar starts with A at the top regardless of how bad it is.
    # `sorted` is stable, so identifier order survives inside each group and the column
    # still lines up with the recommendations below.
    for check in sorted(report.checks, key=lambda item: _ACTION_ORDER.get(item.outcome, 0)):
        column = _CHECK_COLUMNS.get(check.outcome)
        if column is None:
            # `not_applicable`, and anything a future methodology records that this
            # renderer has not been taught. Counted either way: an outcome nobody
            # anticipated must still show up in the total rather than vanish from it.
            not_applicable += 1
            continue
        columns[column].append(
            element(
                "li",
                element("span", "", class_=f"dot dot-{_dot(check.outcome)}"),
                _pick(locale, check.title_ro, check.title_en),
            )
        )

    cells = [
        element(
            "td",
            element(
                "h3",
                f"{_text(locale, f'checked_{name}')} ({len(items)})",
            ),
            element("ul", *items),
            class_=f"col-{name}",
        )
        for name, items in (
            ("ok", columns["ok"]),
            ("action", columns["action"]),
            ("unknown", columns["unknown"]),
        )
    ]

    blocks: list[Node] = [
        element("h2", _text(locale, "checked_heading")),
        element("table", element("tr", *cells), class_="checked"),
    ]
    if columns["unknown"]:
        blocks.append(element("p", _text(locale, "checked_unknown_note"), class_="checked-note"))
    if not_applicable:
        line = f"{not_applicable} {_text(locale, 'checked_not_applicable')}"
        withheld = sum(
            1
            for check in report.checks
            if check.outcome == "not_applicable" and check.check_id in set(report.withheld_checks)
        )
        if withheld:
            line += f" · {withheld} {_text(locale, 'checked_withheld')}"
        blocks.append(element("p", line, class_="checked-na"))
    return element("section", *blocks)


_KNOWN_DOTS = frozenset({"pass", "fail", "warning", "unknown"})


def _dot(outcome: str) -> str:
    """The dot colour for one outcome.

    Failures and warnings share a column because both need action, and carry different
    dots because they do not need the same action. "No SPF record" and "name servers all
    at one provider" are not the same sentence, and one colour for both makes the urgent
    one look routine.
    """
    return {"pass": "ok"}.get(outcome, outcome) if outcome in _KNOWN_DOTS else "unknown"


def _how_scored(report: ReportDocument, locale: str) -> Node:
    """The arithmetic behind the number, and any ceiling that overrode it.

    The report showed a score, a band and six bars, and nothing that let a reader work
    out how one produced the other. A deterministic methodology that does not show its
    working is indistinguishable from an opinion, and an institution disputing a figure
    had nothing to dispute with.

    The cap matters most. A capped score is the one number that cannot be derived from
    the pillars above it -- the arithmetic says one thing and the printed figure says
    another -- so without the ceiling and its reason, the scoring looks arbitrary exactly
    where it is at its most deliberate.
    """
    blocks: list[Node] = [
        element("h2", _text(locale, "how_scored_heading")),
        element("p", _text(locale, "how_scored"), class_="note"),
    ]

    for cap in report.caps_applied:
        justification = _pick(locale, cap.justification_ro, cap.justification_en)
        uncapped = "—" if report.uncapped_score is None else f"{report.uncapped_score:g}"
        blocks.append(element("p", element("strong", _text(locale, "cap_heading"))))
        blocks.append(
            element(
                "p",
                _text(locale, "cap_explained")
                .replace("{ceiling}", f"{cap.ceiling:g}")
                .replace("{uncapped}", uncapped),
                class_="note",
            )
        )
        if justification:
            blocks.append(element("p", justification))

    return element("section", *blocks)


def _findings(report: ReportDocument, locale: str) -> Element:
    ordered = report.findings_by_severity()
    if not ordered:
        return element(
            "section",
            element("h2", _text(locale, "findings")),
            element("p", _text(locale, "no_findings"), class_="note"),
        )
    return element(
        "section",
        element("h2", _text(locale, "findings")),
        *[_finding(finding, locale) for finding in ordered],
    )


def _finding(finding: ReportFinding, locale: str) -> Element:
    severity_label = _TEXT[locale].get(f"severity.{finding.severity}", finding.severity)
    blocks: list[Node] = [
        element(
            "span",
            severity_label,
            class_=f"severity severity-{finding.severity}",
        ),
        # The heading is the check's title, which states the condition that *should*
        # hold -- "SPF is published and valid". A finding is that condition failing, so
        # printing the title alone under "what needs fixing" reads as though the good
        # state were the problem. The label says which way round it is.
        element("p", _text(locale, "requirement_unmet"), class_="unmet"),
        element("h3", _pick(locale, finding.title_ro, finding.title_en)),
        element(
            "p",
            element("span", f"{_TEXT[locale]['affects']}: ", class_="muted"),
            element("span", finding.subject, class_="subject"),
        ),
        element("p", element("strong", _text(locale, "why")), " "),
        element("p", _pick(locale, finding.rationale_ro, finding.rationale_en)),
    ]

    # Before the remediation, deliberately. The evidence is why the instruction follows,
    # and an instruction read before its reason is one somebody applies without checking
    # whether it matches what their own infrastructure actually does.
    blocks.extend(_evidence(finding, locale))

    summary = _pick(
        locale, finding.remediation_summary_ro or "", finding.remediation_summary_en or ""
    )
    steps = finding.remediation_steps_ro if locale == "ro" else finding.remediation_steps_en
    if summary or steps:
        blocks.append(element("p", element("strong", _text(locale, "what_to_do"))))
        if finding.remediation_review_status == "draft":
            blocks.append(element("p", _text(locale, "draft_guidance"), class_="draft"))
        if summary:
            blocks.append(element("p", summary))
        if steps:
            blocks.append(element("ol", *[element("li", step) for step in steps]))

    caveat = _pick(locale, finding.remediation_caveat_ro or "", finding.remediation_caveat_en or "")
    if caveat:
        blocks.append(
            element(
                "div",
                element("strong", _text(locale, "caveat")),
                element("p", caveat),
                class_="caveat",
            )
        )
    return element("article", *blocks, class_="finding")


def _evidence_disclosure(evidence: tuple[ReportEvidence, ...], locale: str) -> Node:
    """The evidence behind a sentence, folded away until somebody wants it.

    It used to be a truncated identifier in brackets, which is not evidence: it proves a
    link exists to whoever can query the database and tells the reader nothing they can
    check or dispute. This puts the observation itself one click away -- what was looked
    at, how it came back, and the values recorded.

    `details` rather than a script, because this document is also rendered to PDF by an
    engine that runs no JavaScript, and a report that needs a runtime to reveal its own
    evidence is one that hides it from whoever reads the printed copy. The print
    stylesheet opens every disclosure for the same reason.
    """
    rows: list[Node] = []
    for item in evidence:
        rows.append(
            element(
                "tr",
                element("td", item.observation_type, class_="ename"),
                element(
                    "td",
                    _TEXT[locale].get(f"obs.{item.status}", item.status),
                    class_="obs-status",
                ),
            )
        )
        rows.extend(
            element(
                "tr",
                element(
                    "td",
                    _attribute_label(locale, item.observation_type, name),
                    class_="ename indented",
                ),
                element("td", _attribute_value(locale, name, value)),
            )
            for name, value in item.attributes
        )

    return element(
        "details",
        element("summary", _text(locale, "insights_evidence")),
        element("table", *rows, class_="evidence"),
        class_="insight-evidence",
    )


def _insights(report: ReportDocument, locale: str) -> Node:
    """The model's reading of this run, after the reviewed findings and never instead.

    The model ran on every assessment for weeks and produced a dozen or more grounded
    sentences each time, all of which were assigned to a field nothing read. An
    institution paid for the analysis and saw only the template catalogue.

    Two things this section does not do, and the reasons are not stylistic. It does not
    replace the remediation steps: those come from a reviewed catalogue that cites the
    standard behind each instruction, and a model improvising "add this DNS record" is
    how somebody's mail stops being delivered. And it does not blend into the findings
    above -- different voice, different styling, and a caption saying who wrote it,
    because a reader deciding what to do with their DNS is entitled to know which
    sentences a person stands behind.

    Every sentence here cited evidence from this run; the grounding validator drops the
    ones that do not, before they ever reach storage. The identifiers travel with the
    text so a reader can still check the link months later.
    """
    if not report.insights:
        return element("section")

    blocks: list[Node] = [
        element("h2", _text(locale, "insights_heading")),
    ]
    for insight in report.insights:
        parts: list[Node] = []
        label = _TEXT[locale].get(f"insight.{insight.kind}")
        if label:
            parts.append(element("span", label, class_="insight-kind"))
        parts.append(element("span", insight.text))
        blocks.append(element("p", *parts, class_="insight"))
        if insight.evidence:
            blocks.append(_evidence_disclosure(insight.evidence, locale))

    return element("section", element("div", *blocks, class_="insights"))


#: How many names of one kind stand open before the rest are folded into a disclosure.
#:
#: A preview, not a cap: every name is in the document either way. This only decides how
#: much of a group meets the eye first, so a section that opens with sixty-two weak names
#: does not teach the reader to skip it.
_ASSET_PREVIEW = 12


def _assets(report: ReportDocument, locale: str) -> Node:
    """Which names were discovered, and how strong the claim is that they belong here.

    The report gave counts -- "83 discovered, 62 low-confidence" -- and nothing else. An
    institution could not tell which 62, why those were weaker, or whether the 20 stronger
    ones were theirs. A number nobody can act on is not disclosure.

    Grouped by basis and ordered strongest first, because the basis is what carries the
    meaning: a subdomain of the authorized domain is a different claim from a name that
    merely resolves to the same address, and listing both as "discovered assets" would
    assert an ownership the platform has not established. The names themselves come from
    public certificate logs -- showing an institution what anybody can already look up
    about it is the point of the section.
    """
    if not report.asset_groups:
        return element("section")

    blocks: list[Node] = [
        element("h2", _text(locale, "assets_heading")),
        element("p", _text(locale, "assets_note"), class_="note"),
    ]
    for group in report.asset_groups:
        label = _TEXT[locale].get(f"basis.{group.basis}", group.basis)
        heading = f"{label} — {_text(locale, 'asset_confidence')} {group.confidence:g}"
        if group.shared_hosting:
            heading += f" · {group.shared_hosting} {_text(locale, 'asset_shared')}"
        blocks.append(element("h3", heading, class_="asset-basis"))
        preview = group.names[:_ASSET_PREVIEW]
        rest = group.names[_ASSET_PREVIEW:]
        blocks.append(element("ul", *(element("li", name) for name in preview), class_="assets"))
        if rest:
            # Folded, not dropped. Sixty-two weak names ahead of the twenty strong ones
            # buries the ones worth acting on, but an institution cannot check a list it
            # cannot see -- so the remainder is one click away, and open on paper, which
            # is the same bargain the evidence disclosures make.
            blocks.append(
                element(
                    "details",
                    element(
                        "summary",
                        f"{_text(locale, 'asset_rest')} ({len(rest)})",
                    ),
                    element(
                        "ul",
                        *(element("li", name) for name in rest),
                        class_="assets",
                    ),
                    class_="asset-rest",
                )
            )

    return element("section", *blocks)


def _not_determined(report: ReportDocument, locale: str) -> Element:
    """What was not established, and what was never attempted.

    These listed bare identifiers -- `D.database_exposed` -- which name the check to
    somebody who maintains the catalogue and nobody else. The reader they are written for
    is being told that part of the assessment did not happen, and "D.database_exposed"
    does not tell them which part.

    The titles are already in the document, carried for the summary above. Using them
    here costs nothing and turns a list of symbols into a list of sentences. The
    identifier stays beside each one, small: an operator disputing a result needs the
    name the catalogue uses.
    """
    titles = {
        check.check_id: _pick(locale, check.title_ro, check.title_en) for check in report.checks
    }

    def entry(check_id: str) -> Node:
        title = titles.get(check_id)
        if title is None:
            return element("li", element("code", check_id))
        return element("li", title, " ", element("code", check_id, class_="check-id"))

    sections: list[Node] = []
    for key, note, items in (
        ("undetermined", "undetermined_note", report.undetermined_checks),
        ("withheld", "withheld_note", report.withheld_checks),
    ):
        if not items:
            continue
        sections.extend(
            [
                element("h2", _text(locale, key)),
                element("p", _text(locale, note), class_="note"),
                element("ul", *[entry(item) for item in items]),
            ]
        )
    return element("section", *sections)


def _footer(report: ReportDocument, locale: str) -> Element:
    return element(
        "footer",
        element("p", _text(locale, "notice")),
        element(
            "dl",
            element("dt", _text(locale, "methodology")),
            element("dd", report.methodology_version),
            element("dt", "policy"),
            # Printed so a disputed report can be checked against the exact catalogue
            # that produced it. Without it "methodology 1.1.0" is a name, not a proof.
            element("dd", element("code", report.policy_digest)),
            element("dt", _text(locale, "mode")),
            element("dd", report.assessment_mode),
            class_="facts",
        ),
    )
