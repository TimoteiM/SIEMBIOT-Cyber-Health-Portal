/**
 * The message catalogue.
 *
 * Romanian is the source language and English is the translation, not the other way
 * round: the primary audience is Romanian public institutions, and writing the
 * originals in English would mean every Romanian string in the product was itself a
 * translation of something written for somebody else.
 *
 * `Messages` is derived from the Romanian catalogue, so English is required to have
 * exactly the same keys -- a missing translation is a type error at build time rather
 * than a Romanian sentence appearing in the middle of an English page.
 *
 * Two things deliberately live outside this file:
 *
 * *Check titles and rationales* come from the policy catalogue, which already carries
 * both languages and is versioned with the methodology. Copying them here would let
 * the copies drift from the policy that produced the finding.
 *
 * *API failures* are looked up by error code, not by the message the server sent. The
 * server's `message` is English developer text; showing it to a Romanian user is how
 * the product currently apologises in the wrong language.
 */

export const LOCALES = ["ro", "en"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "ro";

export function isLocale(value: string | undefined): value is Locale {
  return value !== undefined && (LOCALES as readonly string[]).includes(value);
}

const ro = {
  // -- chrome ---------------------------------------------------------------
  "app.title": "SIEMBIOT Cyber Health Portal",
  "app.description": "Evaluare comunitară a sănătății cibernetice",
  "app.skipToContent": "Sari la conținut",
  "app.privatePortal": "Portal privat",
  "app.workspace": "Spațiu de lucru",
  "app.toggleNavigation": "Comută navigarea",
  "app.collapseMenu": "Restrânge meniul",
  "app.expandMenu": "Extinde meniul",
  "app.language": "Limbă",
  "app.languageRomanian": "Română",
  "app.languageEnglish": "English",

  "nav.overview": "Prezentare generală",
  "nav.domains": "Domenii",
  "nav.assessments": "Evaluări",
  "nav.maturity": "Autoevaluare",
  "nav.team": "Echipă și roluri",
  "nav.audit": "Jurnal de audit",
  "nav.empty": "Creează o organizație pentru a debloca domeniile, echipa și jurnalul de audit.",

  "landing.eyebrow": "Securitate măsurabilă, acces controlat",
  "landing.title": "Bine ai venit în SIEMBIOT Cyber Health Portal",
  "landing.intro": "Autentificarea este asigurată de platforma de identitate a organizației, înainte ca cererea să ajungă la acest portal. Odată autentificat, ești condus direct în spațiul de lucru.",
  "landing.enter": "Continuă către spațiul de lucru",
  "landing.note": "Portalul nu stochează parole și nu emite tokenuri proprii. Drepturile de acces rămân verificate la fiecare cerere, pentru fiecare organizație.",

  // -- onboarding -----------------------------------------------------------
  "onboarding.eyebrow": "Configurare inițială",
  "onboarding.title": "Creează spațiul organizației",
  "onboarding.name": "Numele organizației",
  "onboarding.slug": "Identificator scurt",
  "onboarding.slugHint":
    "Litere mici, cifre și cratime. Trebuie să înceapă și să se termine cu o literă sau o cifră.",
  "onboarding.submit": "Continuă",
  "onboarding.sidebar": "Creează o organizație pentru a debloca domeniile, echipa și jurnalul de audit.",
  "onboarding.chooseEyebrow": "Spații de lucru",
  "onboarding.chooseTitle": "Organizațiile tale",
  "onboarding.chooseIntro": "Alege organizația pe care vrei să o vezi.",
  "onboarding.createAnother": "Creează o organizație nouă",
  "onboarding.viaSupportAccess": "Acces de suport",

  // -- alegerea identității (numai în dezvoltare) ----------------------------
  "signIn.eyebrow": "Acces local",
  "signIn.title": "Alege identitatea",
  "signIn.notRealAuthentication":
    "Aceasta nu este o autentificare. În implementările reale identitatea este stabilită de platforma de identitate a organizației, înainte ca cererea să ajungă aici. Pagina există doar pentru lucrul local și nu funcționează în afara mediului de dezvoltare.",
  "signIn.username": "Utilizator",
  "signIn.password": "Parolă",
  "signIn.submit": "Continuă",
  "signIn.rejected": "Utilizator sau parolă necunoscute.",
  "signIn.accountsHeading": "Conturi disponibile",
  "signIn.useAccount": "Folosește",
  "signIn.adminDescription":
    "Administrator de platformă. Vede și organizațiile altora, prin acorduri de acces înregistrate și limitate în timp — nu prin ocolirea izolării.",
  "signIn.expertDescription":
    "Membru al unei organizații. Vede exact ce vede clientul: propria organizație și nimic altceva.",
  "signIn.signedInAs": "Conectat ca {name}",
  "signIn.signOut": "Schimbă identitatea",

  // -- assessments ----------------------------------------------------------
  "assessments.eyebrow": "Evaluări",
  "assessments.title": "Evaluări ale suprafeței externe",
  "assessments.startHeading": "Pornește o evaluare",
  "assessments.recentHeading": "Evaluări recente",
  "assessments.passiveExplainer":
    "citește doar ce publică deja domeniul: DNS, RDAP, Certificate Transparency, certificatul TLS și pagina pe care o vede orice vizitator. Nu cere dovada controlului, pentru că nu cere domeniului nimic în plus față de ce oferă tuturor. Acoperă toate cele {count} verificări ale metodologiei.",
  "assessments.authorizedExplainer":
    "poate trece dincolo de ce vede un vizitator, așa că cere control verificat și o autorizare semnată.",
  "assessments.observePublic": "Observă public",
  "assessments.authorizedRun": "Evaluare autorizată",
  "assessments.needsVerification": "Necesită control verificat asupra domeniului.",
  "assessments.unverified": "control neverificat",
  "assessments.noDomains": "Adaugă mai întâi un domeniu.",
  "assessments.none": "Nicio evaluare încă.",
  "assessments.loading": "Încărcăm evaluările…",
  "assessments.loadFailed": "Starea nu a putut fi încărcată.",
  "assessments.queueingPassive": "Punem observarea în coadă…",
  "assessments.queueingAuthorized": "Punem evaluarea autorizată în coadă…",
  "assessments.queuedPassive": "Observarea a fost pusă în coadă. Citim doar date deja publice.",
  "assessments.queuedAuthorized": "Evaluarea autorizată a fost pusă în coadă.",
  "assessments.startFailed": "Evaluarea nu a putut fi pornită.",
  "assessments.cancel": "Anulează",
  "assessments.cancelReason": "Anulată din interfață",
  "assessments.cancelRequested":
    "Anularea a fost cerută; lucrul în curs se oprește la următorul punct sigur.",
  "assessments.cancelFailed": "Anularea nu a putut fi cerută.",
  "assessments.cancelPending": "Anulare cerută; se oprește la următorul punct sigur.",
  "assessments.methodology": "Metodologia {version}",
  "assessments.steps": "Etape ({count})",
  "assessments.progress": "{settled} din {total} etape ({percent}%)",
  "assessments.failedSteps": "{count} eșuate",
  "assessments.coverage": "Acoperire {percent}%",
  "assessments.viewFindings": "Vezi constatările",
  "assessments.insufficientTitle": "Dovezi insuficiente pentru un scor",
  "assessments.insufficientBody":
    "Am putut evalua doar {percent}% din verificări. Sub pragul de {floor}% rezultatul nu este reprezentativ, așa că nu îl prezentăm ca scor.",
  "assessments.rawScore": "Valoare brută, pentru audit: {score} / 100",

  "schedule.label": "Reevaluare automată",
  "schedule.off": "Oprită",
  "schedule.daily": "Zilnic",
  "schedule.weekly": "Săptămânal",
  "schedule.monthly": "Lunar",
  "schedule.quarterly": "Trimestrial",
  "schedule.nextRun": "Următoarea: {when}",
  "schedule.saved": "Cadența a fost salvată.",
  "schedule.saveFailed": "Cadența nu a putut fi salvată.",

  "mode.passive_observation": "Observare publică",
  "mode.authorized_assessment": "Evaluare autorizată",

  "state.draft": "Ciornă",
  "state.awaiting_authorization": "Așteaptă autorizarea",
  "state.queued": "În așteptare",
  "state.planning": "Planificare",
  "state.collecting": "Colectare dovezi",
  "state.normalizing": "Normalizare",
  "state.evaluating": "Evaluare",
  "state.agent_analysis": "Analiză asistată",
  "state.report_generation": "Generare raport",
  "state.completed": "Finalizată",
  "state.partially_completed": "Finalizată parțial",
  "state.cancelled": "Anulată",
  "state.failed": "Eșuată",
  "state.expired": "Expirată",
  "state.blocked_by_policy": "Blocată de politică",

  "step.pending": "în așteptare",
  "step.running": "în curs",
  "step.succeeded": "reușit",
  "step.failed": "eșuat",
  "step.skipped": "omis",
  "step.cancelled": "anulat",
  "step.dead_lettered": "abandonat",

  "band.resilient": "Rezilient",
  "band.managed": "Gestionat",
  "band.developing": "În dezvoltare",
  "band.exposed": "Expus",
  "band.critical": "Critic",
  "band.insufficient_coverage": "Dovezi insuficiente",

  // -- findings -------------------------------------------------------------
  "history.eyebrow": "Evoluție",
  "history.title": "Cum a evoluat",
  "history.loading": "Încărcăm istoricul…",
  "history.loadFailed": "Istoricul nu a putut fi încărcat.",
  "history.none": "Nu există încă evaluări finalizate pentru acest domeniu.",
  "history.single": "O singură evaluare finalizată. Evoluția apare după a doua.",
  "history.chartLabel": "Scor în timp",
  "history.sinceLast": "Față de evaluarea anterioară",
  "history.scoreUp": "Scorul a crescut cu {delta}",
  "history.scoreDown": "Scorul a scăzut cu {delta}",
  "history.scoreSame": "Scorul nu s-a schimbat",
  "history.coverageChange": "Acoperirea s-a schimbat cu {delta} puncte",
  "history.incomparableCoverage": "Cele două evaluări nu au văzut la fel de mult, așa că diferența de scor nu arată o îmbunătățire. Acoperirea s-a schimbat cu {delta} puncte.",
  "history.incomparableInsufficient": "Cel puțin una dintre evaluări a fost sub pragul de acoperire, deci nu are un rezultat cu care să comparăm.",
  "history.resolved": "Rezolvate ({count})",
  "history.opened": "Apărute ({count})",
  "history.unchanged": "{count} constatări rămân deschise de dinainte",
  "history.pointLabel": "{score} din 100 · acoperire {coverage}% · {when}",
  "history.viewHistory": "Vezi evoluția",

  "findings.eyebrow": "Constatări",
  "findings.title": "Ce am găsit",
  "findings.loading": "Încărcăm constatările…",
  "findings.loadFailed": "Constatările nu au putut fi încărcate.",
  "findings.showResolved": "Arată și constatările rezolvate",
  "findings.none": "Nicio constatare deschisă pentru acest domeniu.",
  "findings.noData": "Nu există încă date pentru acest domeniu.",
  "findings.noAssessment":
    "Nicio evaluare finalizată pentru acest domeniu. Pornește una din pagina Evaluări.",
  "findings.bySeverity": "Constatări pe severitate",
  "findings.group": "{severity} ({count})",
  "findings.coverageRemainder": "Acoperire {percent}% — restul verificărilor nu au putut fi evaluate",
  "findings.insufficientBody":
    "Am putut evalua doar {percent}% din verificări, sub pragul de {floor}%. Lista de mai jos arată ce am găsit, dar nu este completă.",
  "findings.pillar": "Pilon",
  "findings.state": "Stare",
  "findings.seen": "Observat",
  "findings.evidence": "Dovezi",
  "findings.technicalDetails": "Detalii tehnice",
  "findings.check": "Verificare",
  "findings.reason": "Motiv",
  "findings.subject": "Subiect",
  "findings.methodology": "Metodologie",
  "findings.references": "Referințe: {list}",
  "findings.remediationPending":
    "Îndrumare de remediere: {template} — textul complet urmează să fie publicat.",
  "findings.seenToday": "azi",
  "findings.seenYesterday": "de ieri",
  "findings.seenDays": "de {count} zile",
  "findings.confidenceAttribution": "Atribuire incertă ({percent}%)",
  "findings.confidenceFreshness": "Dovadă mai veche ({percent}%)",
  "findings.confidenceSource": "Sursă mai puțin sigură ({percent}%)",

  "remediation.heading": "Ce poți face",
  "remediation.steps": "Pași",
  "remediation.verification": "Cum verifici",
  "remediation.caveat": "De reținut înainte",
  "remediation.draft": "Îndrumare în lucru, încă nerevizuită",
  "remediation.effortLow": "Efort mic",
  "remediation.effortMedium": "Efort mediu",
  "remediation.effortHigh": "Efort mare",
  "remediation.missing": "Nu avem încă îndrumare scrisă pentru această verificare.",

  "roadmap.heading": "Plan de remediere",
  "roadmap.status": "Stare",
  "roadmap.planned": "Planificat",
  "roadmap.in_progress": "În lucru",
  "roadmap.blocked": "Blocat",
  "roadmap.completed": "Finalizat",
  "roadmap.notPlanned": "Neplanificat",
  "roadmap.due": "Termen",
  "roadmap.overdue": "Termen depășit",
  "roadmap.unplanned": "{count} constatări fără plan",
  "roadmap.contradicted": "{count} marcate ca rezolvate, dar încă observate",
  "roadmap.confirmed": "Confirmat de evaluare",
  "roadmap.assertedNotObserved": "Marcat ca finalizat, dar evaluarea încă vede problema. Fie remedierea nu a funcționat, fie a fost aplicată undeva unde evaluarea nu ajunge.",
  "roadmap.resolvedWithoutAction": "Rezolvat fără o acțiune înregistrată",
  "roadmap.saved": "Planul a fost salvat.",
  "roadmap.saveFailed": "Planul nu a putut fi salvat.",

  // -- autoevaluare ---------------------------------------------------------
  // Formularea evită peste tot cuvântul „scor” pentru rezultatul declarat: este o
  // declarație a organizației, nu o măsurătoare, iar cele două nu se adună.
  "maturity.eyebrow": "Autoevaluare",
  "maturity.title": "Ce nu se poate observa din exterior",
  "maturity.intro":
    "Evaluarea tehnică vede domeniul din afară. Nu poate vedea dacă copiile de siguranță se restaurează, dacă cineva ar observa un incident noaptea sau dacă accesul este retras când pleacă un angajat. Acestea se întreabă.",
  "maturity.draftNotice":
    "Întrebările sunt în stadiul de proiect și nu au trecut încă printr-o revizuire de securitate.",
  "maturity.declared": "Rezultat declarat de organizație",
  "maturity.declaredExplained":
    "Un rezultat declarat, nu măsurat. Nu se combină cu scorul evaluării tehnice: sunt două feluri diferite de dovadă, iar o medie ar permite unei declarații încrezătoare să acopere o slăbiciune observată.",
  "maturity.completeness": "Completitudine",
  "maturity.withheld": "Rezultat indisponibil",
  "maturity.insufficientCompleteness":
    "Sub {floor}% completitudine nu se afișează niciun rezultat. Un procent calculat din prea puține răspunsuri arată ca o concluzie, dar nu este una.",
  "maturity.nothingApplicable":
    "Toate întrebările au fost marcate ca neaplicabile, deci nu există nimic de evaluat.",
  "maturity.answered": "Răspunse: {answered} din {total} întrebări aplicabile",
  "maturity.contradicted": "Declarații pe care evaluarea le contrazice: {count}",
  "maturity.sectionScore": "Rezultat declarat: {percentage}%",
  "maturity.sectionUnanswered": "Fără răspunsuri",
  "maturity.notAnswered": "Fără răspuns",
  "maturity.reference": "NIS2, articolul 21 alineatul (2) litera ({letter})",
  "maturity.answeredBy": "{name}, {when}",
  "maturity.saved": "Răspunsul a fost salvat.",
  "maturity.saveFailed": "Răspunsul nu a putut fi salvat.",
  "maturity.loading": "Se încarcă chestionarul…",
  "maturity.loadFailed": "Chestionarul nu a putut fi încărcat.",

  // Relația dintre ce declară organizația și ce observă platforma. Dezacordul
  // primește un paragraf, nu o etichetă: este lucrul cel mai util de pe ecran.
  "maturity.contradictedNotice":
    "Ați declarat că această măsură este aplicată, dar evaluarea observă contrariul. Fie măsura nu funcționează, fie a fost aplicată undeva unde evaluarea nu ajunge.",
  "maturity.understatedNotice":
    "Evaluarea observă că această măsură funcționează, deși ați declarat că nu este aplicată. Merită verificat: efortul poate fi îndreptat altundeva.",
  "maturity.consistentNotice": "Evaluarea tehnică este de acord cu acest răspuns.",
  "maturity.notObservedNotice":
    "Platforma nu a putut verifica acest răspuns. „Nu am putut privi” nu înseamnă „am confirmat”.",

  "maturity.answer.absent": "Nu există.",
  "maturity.answer.informal": "Se face, dar nu este documentat sau consecvent.",
  "maturity.answer.documented": "Documentat și aplicat consecvent.",
  "maturity.answer.verified": "Documentat, aplicat și testat în ultimele 12 luni.",
  "maturity.answer.unknown": "Nu știu.",
  "maturity.answer.not_applicable": "Nu se aplică.",
  // Spus explicit, pentru că este singura opțiune care nu se comportă cum pare.
  "maturity.unknownExplained":
    "„Nu știu” nu se punctează ca „nu”. Reduce completitudinea, pentru că a nu ști este altceva decât a nu avea.",

  // -- publicare ------------------------------------------------------------
  // Consimțământul și publicarea sunt două fapte diferite. O interfață care le
  // confundă ajunge să spună cuiva că este publicat când nu este.
  "publication.heading": "Publicare în observatorul public",
  "publication.explainer":
    "Poți alege ca profilul acestui domeniu să fie vizibil public: banda de rezultat, acoperirea și verificările pe care metodologia le clasifică drept publicabile. Scorul numeric, dovezile și orice identificator nu se publică niciodată.",
  "publication.needsVerification":
    "Publicarea necesită control verificat asupra domeniului. Observarea publică nu cere dovada controlului, dar publicarea unui profil sub numele instituției este altceva.",
  "publication.grant": "Acceptă publicarea",
  "publication.withdraw": "Retrage publicarea",
  "publication.consentedNotPublished":
    "Ai acceptat publicarea. Nu este publicat încă nimic: profilul apare doar după o evaluare finalizată și după avizul de publicare al platformei.",
  "publication.published": "Publicat din {when}.",
  "publication.granted": "Publicarea a fost acceptată.",
  "publication.withdrawn": "Profilul public a fost eliminat.",
  "publication.changeFailed": "Setarea de publicare nu a putut fi modificată.",

  // -- observatorul public --------------------------------------------------
  "observatory.eyebrow": "Observatorul public",
  "observatory.title": "Ce publică instituțiile despre propria igienă cibernetică",
  "observatory.intro":
    "Profilurile de mai jos aparțin organizațiilor care au ales să le facă publice. Fiecare arată banda de rezultat, acoperirea evaluării și verificările pe care metodologia le clasifică drept publicabile.",
  "observatory.consentNotice":
    "Nimic nu apare aici fără acordul explicit al organizației și fără control verificat asupra domeniului. Acordul poate fi retras oricând, iar profilul dispare imediat.",
  "observatory.empty":
    "Nu este publicat niciun profil. Aceasta este starea normală: publicarea necesită atât acordul unei organizații, cât și un aviz de publicare înregistrat.",
  "observatory.unavailable": "Observatorul nu este disponibil momentan.",
  "observatory.count": "{count} profiluri publicate",
  "observatory.coverage": "Acoperire {percent}%",
  "observatory.observed": "Observat la {when}.",
  "observatory.checksHeading": "Verificări publicate",
  "observatory.notice":
    "O evaluare externă de igienă, bazată pe observarea publică și neintruzivă. Nu este o garanție de securitate, un audit, o certificare sau o determinare de conformitate NIS2.",
  "observatory.methodology": "Metodologia {version}, catalog {digest}.",
  "observatory.disputeNotice":
    "Dacă un rezultat vi se pare greșit, organizația care deține domeniul poate retrage publicarea oricând din propriul spațiu de lucru.",

  "result.pass": "Trecut",
  "result.warning": "Atenție",
  "result.fail": "Eșuat",

  "severity.critical": "Critic",
  "severity.high": "Ridicat",
  "severity.medium": "Mediu",
  "severity.low": "Scăzut",
  "severity.informational": "Informativ",

  "findingState.open": "Deschis",
  "findingState.regressed": "Reapărut",
  "findingState.resolved": "Rezolvat",
  "findingState.suppressed": "Suprimat",
  "findingState.accepted_risk": "Risc acceptat",

  "pillar.dns": "DNS și delegare",
  "pillar.email": "Poșta electronică",
  "pillar.web_tls": "Web și TLS",
  "pillar.exposure": "Expunere",
  "pillar.hygiene": "Igienă operațională",
  "pillar.governance": "Guvernanță",

  // -- domains --------------------------------------------------------------
  "domains.eyebrow": "Suprafață autorizată",
  "domains.title": "Domenii",
  "domains.intro": "Adaugă numai domenii pe care organizația are dreptul explicit să le evalueze.",
  "domains.add": "Adaugă domeniul",
  "domains.field": "Numele domeniului",
  "domains.loading": "Încărcăm domeniile…",
  "domains.none": "Nu există încă domenii în organizație.",
  "domains.loadFailed": "Domeniile nu au putut fi încărcate.",
  "domains.adding": "Validăm și înregistrăm domeniul…",
  "domains.addFailed": "Domeniul nu a putut fi adăugat.",
  "domains.viewAudit": "Vezi auditul",

  "domainState.pending.title": "Verificare în așteptare",
  "domainState.pending.detail": "Dovada controlului asupra domeniului nu a fost încă validată.",
  "domainState.verified.title": "Domeniu verificat",
  "domainState.verified.detail": "Serverul a confirmat dovada. Reverificarea periodică rămâne obligatorie.",
  "domainState.expired.title": "Verificare expirată",
  "domainState.expired.detail": "Creează o provocare nouă pentru a relua verificarea.",
  "domainState.failed.title": "Verificare nereușită",
  "domainState.failed.detail": "Bugetul de încercări a fost consumat. Creează o provocare nouă.",
  "domainState.revoked.title": "Acces suspendat",
  "domainState.revoked.detail": "Dovada a fost revocată; nicio evaluare nu este autorizată.",
  "domainState.reverification_required.title": "Reverificare necesară",
  "domainState.reverification_required.detail": "Confirmă din nou controlul înainte de orice operațiune ulterioară.",
  "domainState.instructionsDns": "Publică valoarea exactă într-o înregistrare TXT la {location}.",
  "domainState.instructionsHttps": "Publică valoarea exactă prin HTTPS la {location}; redirecționările sunt verificate strict.",

  // -- domain detail --------------------------------------------------------
  "domainDetail.eyebrow": "Domeniu și autorizare",
  "domainDetail.canonicalTarget": "Ținta canonică exactă: {host}",
  "domainDetail.proofHeading": "1. Dovedește controlul",
  "domainDetail.loading": "Încărcăm starea de securitate…",
  "domainDetail.loadFailed": "Starea nu a putut fi încărcată.",
  "domainDetail.creatingChallenge": "Creăm o dovadă temporară…",
  "domainDetail.secretShownOnce": "Valoarea secretă este afișată o singură dată în această pagină.",
  "domainDetail.challengeFailed": "Dovada nu a putut fi creată.",
  "domainDetail.verifying": "Serverul verifică dovada prin canalul selectat…",
  "domainDetail.verifyFailed": "Verificarea nu a reușit.",
  "domainDetail.recordingConsent": "Înregistrăm consimțământul și domeniul exact…",
  "domainDetail.authorizationDrafted": "Schița autorizării a fost creată. Activarea rămâne un pas explicit.",
  "domainDetail.authorizationFailed": "Autorizarea nu a putut fi creată.",
  "domainDetail.authorizationActive": "Autorizarea semnată de server este activă.",
  "domainDetail.activationFailed": "Autorizarea nu a putut fi activată.",
  "domainDetail.revokeReason": "Revocare explicită solicitată din portal",
  "domainDetail.revoked": "Autorizarea a fost revocată imediat.",
  "domainDetail.revokeFailed": "Revocarea nu a putut fi aplicată.",
  "domainDetail.emergencyActive": "Operațiunile de rețea sunt suspendate printr-un control de urgență.",
  "domainDetail.verified": "Domeniul a fost verificat de server.",

  "domainDetail.method": "Metodă de verificare",
  "domainDetail.methodDns": "Înregistrare DNS TXT",
  "domainDetail.methodHttps": "Fișier HTTPS fix",
  "domainDetail.createChallenge": "Creează dovada",
  "domainDetail.tokenLabel": "Valoare afișată o singură dată",
  "domainDetail.expiresAttempts": "Expiră la {expires}; mai sunt {attempts} încercări.",
  "domainDetail.verifyNow": "Verifică acum",
  "domainDetail.authorizeHeading": "2. Autorizează explicit",
  "domainDetail.consentConfirm": "Confirm că am dreptul să autorizez domeniul exact și intervalul de 24 de ore.",
  "domainDetail.createDraft": "Creează schița autorizării",
  "domainDetail.expiresAt": "expiră la {expires}",
  "domainDetail.signOnServer": "Acceptă și semnează pe server",
  "domainDetail.revoke": "Revocă autorizarea",

  // -- assets ---------------------------------------------------------------
  "assets.eyebrow": "Atribuirea activelor",
  "assets.title": "Candidați descoperiți",
  "assets.intro": "Un nume descoperit public este un candidat, nu un activ confirmat. Nimic nu intră în perimetrul evaluat până când nu accepți explicit.",
  "assets.loading": "Încărcăm candidații…",
  "assets.loadFailed": "Starea nu a putut fi încărcată.",
  "assets.none": "Niciun candidat în așteptare.",
  "assets.toReview": "De revizuit ({count})",
  "assets.decided": "Candidați deja acceptați sau respinși",
  "assets.accept": "Acceptă",
  "assets.reject": "Respinge",
  "assets.accepted": "{name} a fost inclus în perimetrul evaluat.",
  "assets.rejected": "{name} a fost exclus din perimetrul evaluat.",
  "assets.decisionFailed": "Decizia nu a putut fi salvată.",
  "assets.confidence": "încredere {percent}%",
  "assets.confidenceColumn": "Încredere",
  "assets.sharedHosting": "Găzduire partajată: certificatul unui alt client nu spune nimic despre organizația ta.",
  "assets.basis.authorized_domain": "Domeniul autorizat",
  "assets.basis.subdomain": "Subdomeniu al domeniului autorizat",
  "assets.basis.unrelated": "Nume fără legătură evidentă",
  "assets.state.unreviewed": "Nerevizuit",
  "assets.state.accepted": "Acceptat",
  "assets.state.rejected": "Respins",
  "assets.observedTimes": "observat de {count} ori",
  "assets.decidedHeading": "Deja decise ({count})",
  "assets.nameColumn": "Nume",
  "assets.decisionColumn": "Decizie",

  "attribution.shared_certificate": "Certificat partajat",
  "attribution.unrelated_name": "Nume fără legătură evidentă",
  "attribution.subdomain_of_verified": "Subdomeniu al unui domeniu verificat",
  "attribution.user_declared": "Declarat de organizație",
  "attribution.passive_intelligence": "Sursă pasivă",

  // -- team and audit -------------------------------------------------------
  "team.eyebrow": "Control acces",
  "team.title": "Echipă și roluri",
  "team.caption": "Membrii organizației și rolurile active",
  "team.loading": "Încărcăm echipa…",
  "team.none": "Nu există membri de afișat.",
  "team.loadFailed": "Echipa nu a putut fi încărcată.",
  "audit.loading": "Încărcăm jurnalul…",
  "audit.none": "Nu există evenimente de audit.",
  "audit.loadFailed": "Jurnalul nu a putut fi încărcat.",

  "onboarding.checkingIdentity": "Verificăm identitatea…",
  "onboarding.creating": "Creăm organizația…",
  "onboarding.loadFailed": "Starea nu a putut fi încărcată.",

  // -- errors ---------------------------------------------------------------
  // Looked up by the server's stable error code. The server's own message is English
  // developer text and must never reach a reader.
  "error.generic": "Cererea nu a putut fi finalizată.",
  "error.not_found": "Resursa cerută nu a fost găsită.",
  "error.forbidden": "Nu ai permisiunea necesară pentru această acțiune.",
  "error.validation_error": "Datele trimise nu sunt valide.",
  "error.request_rejected": "Cererea a fost respinsă.",
  "error.internal_error": "A apărut o eroare internă. Încearcă din nou.",
  "error.unauthorized": "Identitatea nu a fost primită de la platforma de identitate.",
  "error.ownership_not_verified":
    "Evaluarea autorizată cere control verificat asupra domeniului. Observarea publică nu cere dovada controlului.",
  "error.methodology_unavailable": "Nicio versiune de metodologie nu este publicată.",
  "error.identityMissing":
    "Identitatea nu a fost primită de la platforma de identitate. Reîncarcă pagina sau contactează administratorul.",
} as const;

export type MessageKey = keyof typeof ro;
export type Messages = Record<MessageKey, string>;

const en: Messages = {
  "app.title": "SIEMBIOT Cyber Health Portal",
  "app.description": "Community cyber health assessment",
  "app.skipToContent": "Skip to content",
  "app.privatePortal": "Private portal",
  "app.workspace": "Workspace",
  "app.toggleNavigation": "Toggle navigation",
  "app.collapseMenu": "Collapse menu",
  "app.expandMenu": "Expand menu",
  "app.language": "Language",
  "app.languageRomanian": "Română",
  "app.languageEnglish": "English",

  "nav.overview": "Overview",
  "nav.domains": "Domains",
  "nav.assessments": "Assessments",
  "nav.maturity": "Self-assessment",
  "nav.team": "Team and roles",
  "nav.audit": "Audit log",
  "nav.empty": "Create an organization to unlock domains, the team and the audit log.",

  "landing.eyebrow": "Measurable security, controlled access",
  "landing.title": "Welcome to the SIEMBIOT Cyber Health Portal",
  "landing.intro": "Authentication is handled by your organization's identity platform, before the request reaches this portal. Once authenticated, you are taken straight to the workspace.",
  "landing.enter": "Continue to the workspace",
  "landing.note": "The portal stores no passwords and issues no tokens of its own. Access rights stay checked on every request, for every organization.",

  "onboarding.eyebrow": "Initial setup",
  "onboarding.title": "Create the organization workspace",
  "onboarding.name": "Organization name",
  "onboarding.slug": "Short identifier",
  "onboarding.slugHint":
    "Lower-case letters, digits and hyphens. Must start and end with a letter or a digit.",
  "onboarding.submit": "Continue",
  "onboarding.sidebar": "Create an organization to unlock domains, the team and the audit log.",
  "onboarding.chooseEyebrow": "Workspaces",
  "onboarding.chooseTitle": "Your organizations",
  "onboarding.chooseIntro": "Choose the organization you want to look at.",
  "onboarding.createAnother": "Create a new organization",
  "onboarding.viaSupportAccess": "Support access",

  // -- choosing an identity (development only) ------------------------------
  "signIn.eyebrow": "Local access",
  "signIn.title": "Choose an identity",
  "signIn.notRealAuthentication":
    "This is not authentication. In real deployments identity is established by the organization's identity platform before the request reaches here. This page exists for local work only and does nothing outside a development build.",
  "signIn.username": "User",
  "signIn.password": "Password",
  "signIn.submit": "Continue",
  "signIn.rejected": "Unknown user or password.",
  "signIn.accountsHeading": "Available accounts",
  "signIn.useAccount": "Use",
  "signIn.adminDescription":
    "Platform administrator. Sees other organizations through recorded, time-bounded access grants — not by bypassing isolation.",
  "signIn.expertDescription":
    "A member of one organization. Sees exactly what a client sees: their own organization and nothing else.",
  "signIn.signedInAs": "Signed in as {name}",
  "signIn.signOut": "Change identity",

  "assessments.eyebrow": "Assessments",
  "assessments.title": "External surface assessments",
  "assessments.startHeading": "Start an assessment",
  "assessments.recentHeading": "Recent assessments",
  "assessments.passiveExplainer":
    "reads only what the domain already publishes: DNS, RDAP, Certificate Transparency, the TLS certificate and the page any visitor sees. It needs no proof of control, because it asks the domain for nothing beyond what it offers everyone. It covers all {count} checks in the methodology.",
  "assessments.authorizedExplainer":
    "can reach past what a visitor sees, so it requires verified control and a signed authorization.",
  "assessments.observePublic": "Observe publicly",
  "assessments.authorizedRun": "Authorized assessment",
  "assessments.needsVerification": "Requires verified control of the domain.",
  "assessments.unverified": "control not verified",
  "assessments.noDomains": "Add a domain first.",
  "assessments.none": "No assessments yet.",
  "assessments.loading": "Loading assessments…",
  "assessments.loadFailed": "The status could not be loaded.",
  "assessments.queueingPassive": "Queueing the observation…",
  "assessments.queueingAuthorized": "Queueing the authorized assessment…",
  "assessments.queuedPassive": "The observation is queued. We read only data that is already public.",
  "assessments.queuedAuthorized": "The authorized assessment is queued.",
  "assessments.startFailed": "The assessment could not be started.",
  "assessments.cancel": "Cancel",
  "assessments.cancelReason": "Cancelled from the interface",
  "assessments.cancelRequested":
    "Cancellation requested; work in progress stops at the next safe point.",
  "assessments.cancelFailed": "Cancellation could not be requested.",
  "assessments.cancelPending": "Cancellation requested; it stops at the next safe point.",
  "assessments.methodology": "Methodology {version}",
  "assessments.steps": "Steps ({count})",
  "assessments.progress": "{settled} of {total} steps ({percent}%)",
  "assessments.failedSteps": "{count} failed",
  "assessments.coverage": "Coverage {percent}%",
  "assessments.viewFindings": "View findings",
  "assessments.insufficientTitle": "Not enough evidence for a score",
  "assessments.insufficientBody":
    "We could evaluate only {percent}% of the checks. Below the {floor}% threshold the result is not representative, so we do not present it as a score.",
  "assessments.rawScore": "Raw value, for audit: {score} / 100",

  "schedule.label": "Automatic reassessment",
  "schedule.off": "Off",
  "schedule.daily": "Daily",
  "schedule.weekly": "Weekly",
  "schedule.monthly": "Monthly",
  "schedule.quarterly": "Quarterly",
  "schedule.nextRun": "Next: {when}",
  "schedule.saved": "The cadence was saved.",
  "schedule.saveFailed": "The cadence could not be saved.",

  "mode.passive_observation": "Public observation",
  "mode.authorized_assessment": "Authorized assessment",

  "state.draft": "Draft",
  "state.awaiting_authorization": "Awaiting authorization",
  "state.queued": "Queued",
  "state.planning": "Planning",
  "state.collecting": "Collecting evidence",
  "state.normalizing": "Normalizing",
  "state.evaluating": "Evaluating",
  "state.agent_analysis": "Assisted analysis",
  "state.report_generation": "Generating report",
  "state.completed": "Completed",
  "state.partially_completed": "Partially completed",
  "state.cancelled": "Cancelled",
  "state.failed": "Failed",
  "state.expired": "Expired",
  "state.blocked_by_policy": "Blocked by policy",

  "step.pending": "pending",
  "step.running": "running",
  "step.succeeded": "succeeded",
  "step.failed": "failed",
  "step.skipped": "skipped",
  "step.cancelled": "cancelled",
  "step.dead_lettered": "dead-lettered",

  "band.resilient": "Resilient",
  "band.managed": "Managed",
  "band.developing": "Developing",
  "band.exposed": "Exposed",
  "band.critical": "Critical",
  "band.insufficient_coverage": "Not enough evidence",

  "history.eyebrow": "Trend",
  "history.title": "How it has changed",
  "history.loading": "Loading history…",
  "history.loadFailed": "The history could not be loaded.",
  "history.none": "No completed assessments for this domain yet.",
  "history.single": "Only one completed assessment. A trend appears after the second.",
  "history.chartLabel": "Score over time",
  "history.sinceLast": "Compared with the previous assessment",
  "history.scoreUp": "The score rose by {delta}",
  "history.scoreDown": "The score fell by {delta}",
  "history.scoreSame": "The score did not change",
  "history.coverageChange": "Coverage changed by {delta} points",
  "history.incomparableCoverage": "The two assessments did not see the same amount, so the difference in score does not show an improvement. Coverage changed by {delta} points.",
  "history.incomparableInsufficient": "At least one of the assessments was below the coverage floor, so it has no result to compare against.",
  "history.resolved": "Resolved ({count})",
  "history.opened": "Appeared ({count})",
  "history.unchanged": "{count} findings remain open from before",
  "history.pointLabel": "{score} of 100 · coverage {coverage}% · {when}",
  "history.viewHistory": "View trend",

  "findings.eyebrow": "Findings",
  "findings.title": "What we found",
  "findings.loading": "Loading findings…",
  "findings.loadFailed": "The findings could not be loaded.",
  "findings.showResolved": "Also show resolved findings",
  "findings.none": "No open findings for this domain.",
  "findings.noData": "There is no data for this domain yet.",
  "findings.noAssessment":
    "No completed assessment for this domain. Start one from the Assessments page.",
  "findings.bySeverity": "Findings by severity",
  "findings.group": "{severity} ({count})",
  "findings.coverageRemainder": "Coverage {percent}% — the remaining checks could not be evaluated",
  "findings.insufficientBody":
    "We could evaluate only {percent}% of the checks, below the {floor}% threshold. The list below shows what we found, but it is not complete.",
  "findings.pillar": "Pillar",
  "findings.state": "State",
  "findings.seen": "Seen",
  "findings.evidence": "Evidence",
  "findings.technicalDetails": "Technical details",
  "findings.check": "Check",
  "findings.reason": "Reason",
  "findings.subject": "Subject",
  "findings.methodology": "Methodology",
  "findings.references": "References: {list}",
  "findings.remediationPending":
    "Remediation guidance: {template} — the full text is yet to be published.",
  "findings.seenToday": "today",
  "findings.seenYesterday": "since yesterday",
  "findings.seenDays": "for {count} days",
  "findings.confidenceAttribution": "Attribution uncertain ({percent}%)",
  "findings.confidenceFreshness": "Older evidence ({percent}%)",
  "findings.confidenceSource": "Less reliable source ({percent}%)",

  "remediation.heading": "What you can do",
  "remediation.steps": "Steps",
  "remediation.verification": "How to check",
  "remediation.caveat": "Read before you start",
  "remediation.draft": "Draft guidance, not yet reviewed",
  "remediation.effortLow": "Low effort",
  "remediation.effortMedium": "Medium effort",
  "remediation.effortHigh": "High effort",
  "remediation.missing": "We have no written guidance for this check yet.",

  "roadmap.heading": "Remediation plan",
  "roadmap.status": "Status",
  "roadmap.planned": "Planned",
  "roadmap.in_progress": "In progress",
  "roadmap.blocked": "Blocked",
  "roadmap.completed": "Completed",
  "roadmap.notPlanned": "Not planned",
  "roadmap.due": "Due",
  "roadmap.overdue": "Overdue",
  "roadmap.unplanned": "{count} findings with no plan",
  "roadmap.contradicted": "{count} marked done but still observed",
  "roadmap.confirmed": "Confirmed by assessment",
  "roadmap.assertedNotObserved": "Marked complete, but the assessment still sees the problem. Either the fix did not work, or it was applied somewhere the assessment does not reach.",
  "roadmap.resolvedWithoutAction": "Resolved with no recorded action",
  "roadmap.saved": "The plan was saved.",
  "roadmap.saveFailed": "The plan could not be saved.",

  // -- self-assessment ------------------------------------------------------
  "maturity.eyebrow": "Self-assessment",
  "maturity.title": "What cannot be observed from outside",
  "maturity.intro":
    "The technical assessment sees the domain from outside. It cannot see whether backups restore, whether anybody would notice an incident at night, or whether access is withdrawn when somebody leaves. Those get asked.",
  "maturity.draftNotice":
    "These questions are a draft and have not yet been through security review.",
  "maturity.declared": "Declared by the organisation",
  "maturity.declaredExplained":
    "A declared result, not a measured one. It is not combined with the technical score: they are different kinds of evidence, and an average would let a confident declaration cover a weakness that was observed.",
  "maturity.completeness": "Completeness",
  "maturity.withheld": "No result available",
  "maturity.insufficientCompleteness":
    "Below {floor}% completeness no result is shown. A percentage drawn from too few answers looks like a conclusion without being one.",
  "maturity.nothingApplicable":
    "Every question was marked not applicable, so there is nothing to assess.",
  "maturity.answered": "Answered: {answered} of {total} applicable questions",
  "maturity.contradicted": "Declarations the assessment disagrees with: {count}",
  "maturity.sectionScore": "Declared: {percentage}%",
  "maturity.sectionUnanswered": "No answers",
  "maturity.notAnswered": "Not answered",
  "maturity.reference": "NIS2, Article 21(2)({letter})",
  "maturity.answeredBy": "{name}, {when}",
  "maturity.saved": "The answer was saved.",
  "maturity.saveFailed": "The answer could not be saved.",
  "maturity.loading": "Loading the questionnaire…",
  "maturity.loadFailed": "The questionnaire could not be loaded.",

  "maturity.contradictedNotice":
    "You declared this measure is in place, but the assessment observes otherwise. Either the measure is not working, or it was applied somewhere the assessment does not reach.",
  "maturity.understatedNotice":
    "The assessment observes this working, although you declared it is not in place. Worth checking: effort may be better spent elsewhere.",
  "maturity.consistentNotice": "The technical assessment agrees with this answer.",
  "maturity.notObservedNotice":
    "The platform could not check this answer. “We could not look” does not mean “we confirmed”.",

  "maturity.answer.absent": "Not in place.",
  "maturity.answer.informal": "Done, but not written down or not consistent.",
  "maturity.answer.documented": "Documented and applied consistently.",
  "maturity.answer.verified": "Documented, applied, and tested in the last 12 months.",
  "maturity.answer.unknown": "I do not know.",
  "maturity.answer.not_applicable": "Does not apply.",
  "maturity.unknownExplained":
    "“I do not know” does not score as “no”. It reduces completeness, because not knowing is different from not having.",

  // -- publication ----------------------------------------------------------
  "publication.heading": "Publication in the public observatory",
  "publication.explainer":
    "You can choose to make this domain's profile publicly visible: the result band, the coverage, and the checks the methodology classifies as publishable. The numeric score, the evidence and any identifier are never published.",
  "publication.needsVerification":
    "Publication requires verified control of the domain. Public observation needs no proof of control, but publishing a profile under the institution's name is a different matter.",
  "publication.grant": "Agree to publication",
  "publication.withdraw": "Withdraw publication",
  "publication.consentedNotPublished":
    "You have agreed to publication. Nothing is published yet: a profile appears only after a completed assessment and the platform's own publication review.",
  "publication.published": "Published since {when}.",
  "publication.granted": "Publication was agreed.",
  "publication.withdrawn": "The public profile was removed.",
  "publication.changeFailed": "The publication setting could not be changed.",

  // -- the public observatory -----------------------------------------------
  "observatory.eyebrow": "The public observatory",
  "observatory.title": "What institutions publish about their own cyber hygiene",
  "observatory.intro":
    "The profiles below belong to organisations that chose to make them public. Each shows the result band, the assessment's coverage, and the checks the methodology classifies as publishable.",
  "observatory.consentNotice":
    "Nothing appears here without the organisation's explicit agreement and verified control of the domain. Agreement can be withdrawn at any time, and the profile disappears immediately.",
  "observatory.empty":
    "No profile is published. This is the ordinary state: publishing requires both an organisation's agreement and a recorded publication review.",
  "observatory.unavailable": "The observatory is temporarily unavailable.",
  "observatory.count": "{count} published profiles",
  "observatory.coverage": "Coverage {percent}%",
  "observatory.observed": "Observed at {when}.",
  "observatory.checksHeading": "Published checks",
  "observatory.notice":
    "An external hygiene assessment based on public, non-intrusive observation. Not a security guarantee, an audit, a certification, or a NIS2 conformity determination.",
  "observatory.methodology": "Methodology {version}, catalogue {digest}.",
  "observatory.disputeNotice":
    "If a result looks wrong to you, the organisation that holds the domain can withdraw publication at any time from its own workspace.",

  "result.pass": "Pass",
  "result.warning": "Warning",
  "result.fail": "Fail",

  "severity.critical": "Critical",
  "severity.high": "High",
  "severity.medium": "Medium",
  "severity.low": "Low",
  "severity.informational": "Informational",

  "findingState.open": "Open",
  "findingState.regressed": "Regressed",
  "findingState.resolved": "Resolved",
  "findingState.suppressed": "Suppressed",
  "findingState.accepted_risk": "Accepted risk",

  "pillar.dns": "DNS and delegation",
  "pillar.email": "Email",
  "pillar.web_tls": "Web and TLS",
  "pillar.exposure": "Exposure",
  "pillar.hygiene": "Operational hygiene",
  "pillar.governance": "Governance",

  "domains.eyebrow": "Authorized surface",
  "domains.title": "Domains",
  "domains.intro": "Add only domains the organization has an explicit right to assess.",
  "domains.add": "Add the domain",
  "domains.field": "Domain name",
  "domains.loading": "Loading domains…",
  "domains.none": "No domains in the organization yet.",
  "domains.loadFailed": "The domains could not be loaded.",
  "domains.adding": "Validating and recording the domain…",
  "domains.addFailed": "The domain could not be added.",
  "domains.viewAudit": "View the audit log",

  "domainState.pending.title": "Verification pending",
  "domainState.pending.detail": "Proof of control over the domain has not been validated yet.",
  "domainState.verified.title": "Domain verified",
  "domainState.verified.detail": "The server confirmed the proof. Periodic re-verification remains required.",
  "domainState.expired.title": "Verification expired",
  "domainState.expired.detail": "Create a new challenge to resume verification.",
  "domainState.failed.title": "Verification failed",
  "domainState.failed.detail": "The attempt budget is spent. Create a new challenge.",
  "domainState.revoked.title": "Access suspended",
  "domainState.revoked.detail": "The proof was revoked; no assessment is authorized.",
  "domainState.reverification_required.title": "Re-verification required",
  "domainState.reverification_required.detail": "Confirm control again before any further operation.",
  "domainState.instructionsDns": "Publish the exact value in a TXT record at {location}.",
  "domainState.instructionsHttps": "Publish the exact value over HTTPS at {location}; redirects are checked strictly.",

  "domainDetail.eyebrow": "Domain and authorization",
  "domainDetail.canonicalTarget": "Exact canonical target: {host}",
  "domainDetail.proofHeading": "1. Prove control",
  "domainDetail.loading": "Loading the security state…",
  "domainDetail.loadFailed": "The state could not be loaded.",
  "domainDetail.creatingChallenge": "Creating a temporary proof…",
  "domainDetail.secretShownOnce": "The secret value is shown once, on this page only.",
  "domainDetail.challengeFailed": "The proof could not be created.",
  "domainDetail.verifying": "The server is checking the proof over the selected channel…",
  "domainDetail.verifyFailed": "Verification did not succeed.",
  "domainDetail.recordingConsent": "Recording the consent and the exact domain…",
  "domainDetail.authorizationDrafted": "The authorization draft was created. Activation remains an explicit step.",
  "domainDetail.authorizationFailed": "The authorization could not be created.",
  "domainDetail.authorizationActive": "The server-signed authorization is active.",
  "domainDetail.activationFailed": "The authorization could not be activated.",
  "domainDetail.revokeReason": "Explicit revocation requested from the portal",
  "domainDetail.revoked": "The authorization was revoked immediately.",
  "domainDetail.revokeFailed": "The revocation could not be applied.",
  "domainDetail.emergencyActive": "Network operations are suspended by an emergency control.",
  "domainDetail.verified": "The server verified the domain.",

  "domainDetail.method": "Verification method",
  "domainDetail.methodDns": "DNS TXT record",
  "domainDetail.methodHttps": "Fixed HTTPS file",
  "domainDetail.createChallenge": "Create the proof",
  "domainDetail.tokenLabel": "Value shown once only",
  "domainDetail.expiresAttempts": "Expires at {expires}; {attempts} attempts remain.",
  "domainDetail.verifyNow": "Verify now",
  "domainDetail.authorizeHeading": "2. Authorize explicitly",
  "domainDetail.consentConfirm": "I confirm I have the right to authorize this exact domain and the 24-hour period.",
  "domainDetail.createDraft": "Create the authorization draft",
  "domainDetail.expiresAt": "expires at {expires}",
  "domainDetail.signOnServer": "Accept and sign on the server",
  "domainDetail.revoke": "Revoke the authorization",

  "assets.eyebrow": "Asset attribution",
  "assets.title": "Discovered candidates",
  "assets.intro": "A publicly discovered name is a candidate, not a confirmed asset. Nothing enters the assessed perimeter until you accept it explicitly.",
  "assets.loading": "Loading candidates…",
  "assets.loadFailed": "The state could not be loaded.",
  "assets.none": "No candidates awaiting review.",
  "assets.toReview": "To review ({count})",
  "assets.decided": "Candidates already accepted or rejected",
  "assets.accept": "Accept",
  "assets.reject": "Reject",
  "assets.accepted": "{name} was included in the assessed perimeter.",
  "assets.rejected": "{name} was excluded from the assessed perimeter.",
  "assets.decisionFailed": "The decision could not be saved.",
  "assets.confidence": "confidence {percent}%",
  "assets.confidenceColumn": "Confidence",
  "assets.sharedHosting": "Shared hosting: another customer's certificate says nothing about your organization.",
  "assets.basis.authorized_domain": "The authorized domain",
  "assets.basis.subdomain": "Subdomain of the authorized domain",
  "assets.basis.unrelated": "Name with no evident connection",
  "assets.state.unreviewed": "Unreviewed",
  "assets.state.accepted": "Accepted",
  "assets.state.rejected": "Rejected",
  "assets.observedTimes": "observed {count} times",
  "assets.decidedHeading": "Already decided ({count})",
  "assets.nameColumn": "Name",
  "assets.decisionColumn": "Decision",

  "attribution.shared_certificate": "Shared certificate",
  "attribution.unrelated_name": "No evident relation to the name",
  "attribution.subdomain_of_verified": "Subdomain of a verified domain",
  "attribution.user_declared": "Declared by the organization",
  "attribution.passive_intelligence": "Passive source",

  "team.eyebrow": "Access control",
  "team.title": "Team and roles",
  "team.caption": "Organization members and their active roles",
  "team.loading": "Loading the team…",
  "team.none": "No members to show.",
  "team.loadFailed": "The team could not be loaded.",
  "audit.loading": "Loading the log…",
  "audit.none": "No audit events.",
  "audit.loadFailed": "The log could not be loaded.",

  "onboarding.checkingIdentity": "Checking identity…",
  "onboarding.creating": "Creating the organization…",
  "onboarding.loadFailed": "The state could not be loaded.",

  "error.generic": "The request could not be completed.",
  "error.not_found": "The requested resource was not found.",
  "error.forbidden": "You do not have permission for this action.",
  "error.validation_error": "The submitted data is not valid.",
  "error.request_rejected": "The request was rejected.",
  "error.internal_error": "An internal error occurred. Please try again.",
  "error.unauthorized": "Identity was not received from the identity platform.",
  "error.ownership_not_verified":
    "An authorized assessment requires verified control of the domain. Public observation needs no proof of control.",
  "error.methodology_unavailable": "No methodology version is published.",
  "error.identityMissing":
    "Identity was not received from the identity platform. Reload the page or contact your administrator.",
};

export const CATALOGUES: Record<Locale, Messages> = { ro, en };
