"""A fictional institution, complete enough to walk the whole product in the interface.

    python scripts/seed_demo.py

Every real feature of this platform needs data that took a real assessment to produce,
and several of them -- publication above all -- need a domain whose control was proved.
Neither is available on a laptop, so a demonstration either fakes something or shows
empty screens. This script fakes it, loudly, in one place, and refuses to do so anywhere
that could matter.

**Everything it writes is fictional and says so.** The organisation is invented, and the
domains are under `.test`, which RFC 2606 reserves precisely so that nobody's real
infrastructure is ever named by an example. The scores are hand-written, not measured.

**It refuses to run outside development.** Seeded data is indistinguishable from measured
data once it is in the tables -- that is what makes it useful for a demonstration and
what makes it dangerous anywhere else. The environment check and the reserved-name check
are both required, because either alone is a mistake somebody can make in one step.

**It is idempotent.** Identifiers are derived from a fixed namespace, so running it twice
updates rather than accumulating, and the URLs in a written walkthrough keep working.

The one thing it does not do is invent a publication review. Publishing requires a named
person to have approved it, and a demo that forges that signature would be practising
exactly the thing the interlock exists to prevent. `--approve-publication` records one
under an obviously fictional reviewer, and it is opt-in for that reason.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api" / "src"))

#: A fixed namespace, so every run produces the same identifiers and a walkthrough's
#: links keep working.
NAMESPACE = uuid5(NAMESPACE_URL, "https://siembiot.test/demo/v1")

#: RFC 2606 reserves these for documentation and testing. A demonstration that names a
#: real institution's domain publishes a claim about them that nobody assessed.
RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")

ORGANIZATION_NAME = "Primăria Orașului Exemplu (fictiv)"
ORGANIZATION_SLUG = "primaria-exemplu-demo"
PRIMARY_HOST = "primaria-exemplu.test"
SECONDARY_HOST = "servicii.primaria-exemplu.test"

PEOPLE = (
    ("demo-primar", "primar@primaria-exemplu.test", "Elena Marinescu", "organization_owner"),
    ("demo-it", "it@primaria-exemplu.test", "Andrei Dobre", "security_admin"),
)

#: A plausible mix rather than a flattering one: a small institution that has done the
#: visible things and not the invisible ones. Only the 17 checks the catalogue permits
#: on a public profile can ever be published; the rest stay private wherever they land.
EVALUATIONS: dict[str, tuple[str, str]] = {
    # check_id: (result, pillar)
    "A.dnssec_enabled": ("fail", "dns"),
    "A.caa_present": ("fail", "dns"),
    "A.nameserver_diversity": ("pass", "dns"),
    "A.registration_expiry": ("pass", "dns"),
    "B.spf_present": ("pass", "email"),
    "B.dmarc_enforced": ("fail", "email"),
    "B.dkim_declared_present": ("warning", "email"),
    "B.mta_sts_enforced": ("fail", "email"),
    "B.tls_rpt_present": ("fail", "email"),
    "C.https_available": ("pass", "web_tls"),
    "C.http_redirects_https": ("pass", "web_tls"),
    "C.certificate_validity": ("pass", "web_tls"),
    "C.certificate_hostname": ("pass", "web_tls"),
    "C.hsts_present": ("fail", "web_tls"),
    "C.security_headers": ("warning", "web_tls"),
    "C.tls_protocol_posture": ("pass", "web_tls"),
    "C.cookie_attributes": ("warning", "web_tls"),
    "D.wildcard_dns_exposure": ("pass", "attack_surface"),
    "D.asset_attribution_reviewed": ("pass", "attack_surface"),
    "E.domain_reputation_clean": ("pass", "reputation"),
    "F.evidence_freshness": ("pass", "exposure_hygiene"),
    "F.server_banner_disclosure": ("warning", "exposure_hygiene"),
}

#: An earlier run, so the history page has two points and a real delta to describe.
PREVIOUS_OVERRIDES = {"C.https_available": "fail", "C.certificate_validity": "fail"}

SEVERITIES = {"fail": "high", "warning": "medium", "pass": "informational"}

#: Answered enough to clear the completeness floor, and answered honestly -- including
#: one claim the assessment contradicts, because that pairing is the point of the
#: questionnaire and a demo that hides it demonstrates the wrong thing.
MATURITY_ANSWERS = {
    "risk_management.assessment_performed": "informal",
    "risk_management.policy_approved": "documented",
    "risk_management.treatment_owned": "absent",
    "incident_handling.procedure_exists": "documented",
    "incident_handling.reporting_obligation_known": "informal",
    "incident_handling.contact_reachable": "absent",
    "continuity.backups_exist": "documented",
    "continuity.restore_tested": "absent",
    "continuity.copy_isolated": "informal",
    "continuity.plan_exists": "absent",
    "supply_chain.suppliers_inventoried": "informal",
    "supply_chain.security_requirements": "absent",
    "supply_chain.incident_notification": "absent",
    "secure_operations.vulnerability_monitoring": "informal",
    "secure_operations.patching_timeline": "documented",
    "secure_operations.disclosure_contact": "absent",
    "effectiveness.measures_reviewed": "informal",
    "effectiveness.independent_check": "absent",
    "hygiene_training.awareness_training": "documented",
    "hygiene_training.phishing_exercise": "absent",
    # Claimed in place. The assessment sees DMARC failing, and the questionnaire says so.
    "hygiene_training.email_authentication": "verified",
    "cryptography.public_services_encrypted": "documented",
    "cryptography.data_at_rest": "informal",
    "cryptography.key_management": "informal",
    "access_and_assets.inventory_maintained": "documented",
    "access_and_assets.access_reviewed": "informal",
    "access_and_assets.leaver_process": "documented",
    "access_and_assets.privileged_separate": "absent",
    "authentication.mfa_remote_access": "documented",
    "authentication.mfa_privileged": "informal",
    "authentication.emergency_communications": "absent",
}


def use_utf8_output() -> None:
    """Windows consoles still default to cp1252, which cannot encode Romanian.

    Found by running this: the seed completed, and then printing the organisation's name
    raised `UnicodeEncodeError` -- so the last thing the operator saw was a traceback
    after a successful run. A product whose primary audience writes in Romanian should
    not be unable to print its own demonstration data.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def identifier(*parts: str) -> UUID:
    return uuid5(NAMESPACE, "/".join(parts))


def refuse_unless_safe(url: str) -> None:
    """Two independent checks, because either alone is one mistake away from production.

    Seeded rows are indistinguishable from measured ones once written. That is what makes
    them useful here and what makes them unacceptable anywhere a person might read them
    as an assessment of a real institution.
    """
    environment = os.environ.get("SIEMBIOT_ENV", "development")
    if environment != "development":
        raise SystemExit(
            f"refusing to seed demonstration data with SIEMBIOT_ENV={environment!r}. "
            "This writes invented scores that are indistinguishable from measured ones."
        )
    for host in (PRIMARY_HOST, SECONDARY_HOST):
        if not host.endswith(RESERVED_SUFFIXES):
            raise SystemExit(f"{host} is not a reserved name; refusing to seed it")
    if "amazonaws" in url or "rds" in url:
        raise SystemExit("the database URL looks managed; refusing to seed it")


def database_url() -> str:
    url = os.environ.get("SIEMBIOT_DATABASE_URL")
    if not url:
        raise SystemExit("SIEMBIOT_DATABASE_URL is required (the owner role, not the app role)")
    return url.replace("postgresql://", "postgresql+psycopg://")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--approve-publication",
        action="store_true",
        help=(
            "also record a publication review under a fictional reviewer and project the "
            "primary domain into the observatory. Opt-in because forging that signature "
            "is exactly what the interlock exists to prevent."
        ),
    )
    arguments = parser.parse_args()
    use_utf8_output()

    from siembiot.publication import publish_domain
    from sqlalchemy import create_engine, text

    url = database_url()
    refuse_unless_safe(url)
    engine = create_engine(url)

    now = datetime.now(UTC)
    organization_id = identifier("organization")
    people = {
        subject: (identifier("user", subject), email, name, role)
        for subject, email, name, role in PEOPLE
    }
    owner_id = people["demo-primar"][0]
    domains = {
        PRIMARY_HOST: identifier("domain", PRIMARY_HOST),
        SECONDARY_HOST: identifier("domain", SECONDARY_HOST),
    }

    with engine.begin() as connection:
        digest = connection.execute(
            text("SELECT policy_digest FROM methodology_versions ORDER BY version DESC LIMIT 1")
        ).scalar_one_or_none()
        if digest is None:
            raise SystemExit(
                "no methodology version is registered; run scripts/publish_methodology.py first"
            )
        methodology = connection.execute(
            text("SELECT version FROM methodology_versions ORDER BY version DESC LIMIT 1")
        ).scalar_one()

        for subject, (user_id, email, name, _role) in people.items():
            connection.execute(
                text(
                    """
                    INSERT INTO users (id, identity_issuer, identity_subject, email, display_name)
                    VALUES (:id, 'https://idp.local.test', :subject, :email, :name)
                    ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name
                    """
                ),
                {"id": user_id, "subject": subject, "email": email, "name": name},
            )

        connection.execute(
            text(
                """
                INSERT INTO organizations (id, name, slug, created_by_user_id)
                VALUES (:id, :name, :slug, :owner)
                ON CONFLICT (id) DO UPDATE SET name = excluded.name
                """
            ),
            {
                "id": organization_id,
                "name": ORGANIZATION_NAME,
                "slug": ORGANIZATION_SLUG,
                "owner": owner_id,
            },
        )

        for _subject, (user_id, _email, _name, role) in people.items():
            connection.execute(
                text(
                    """
                    INSERT INTO memberships (organization_id, user_id, role, status)
                    VALUES (:organization_id, :user_id, :role, 'active')
                    ON CONFLICT (organization_id, user_id) DO UPDATE SET
                        role = excluded.role, status = 'active'
                    """
                ),
                {"organization_id": organization_id, "user_id": user_id, "role": role},
            )

        for host, domain_id in domains.items():
            # Verified, which on a real domain requires publishing a one-time token in
            # DNS. There is no zone to publish into here, so the state is asserted -- the
            # single most fictional thing this script writes, and the reason it refuses
            # to run anywhere but development.
            connection.execute(
                text(
                    """
                    INSERT INTO domains (
                        id, organization_id, canonical_name, unicode_display,
                        registrable_domain, ownership_state, created_by_user_id
                    ) VALUES (
                        :id, :organization_id, :host, :host, :registrable, 'verified', :owner
                    )
                    ON CONFLICT (id) DO UPDATE SET ownership_state = 'verified'
                    """
                ),
                {
                    "id": domain_id,
                    "organization_id": organization_id,
                    "host": host,
                    "registrable": PRIMARY_HOST,
                    "owner": owner_id,
                },
            )

        domain_id = domains[PRIMARY_HOST]
        for index, (label, when, overrides) in enumerate(
            (
                ("previous", now - timedelta(days=30), PREVIOUS_OVERRIDES),
                ("latest", now - timedelta(hours=2), {}),
            )
        ):
            _write_assessment(
                connection,
                text,
                organization_id=organization_id,
                domain_id=domain_id,
                host=PRIMARY_HOST,
                methodology=methodology,
                digest=digest,
                label=label,
                when=when,
                overrides=overrides,
                is_latest=index == 1,
            )

        _write_findings(
            connection, text, organization_id=organization_id, domain_id=domain_id, when=now
        )
        _write_maturity(connection, text, organization_id=organization_id, actor=owner_id)
        _write_roadmap(connection, text, organization_id=organization_id, actor=owner_id)

        connection.execute(
            text(
                """
                INSERT INTO publication_consents (organization_id, domain_id, granted_by_user_id)
                VALUES (:organization_id, :domain_id, :actor)
                ON CONFLICT (domain_id) WHERE revoked_at IS NULL DO NOTHING
                """
            ),
            {"organization_id": organization_id, "domain_id": domain_id, "actor": owner_id},
        )

        if arguments.approve_publication:
            connection.execute(
                text(
                    """
                    INSERT INTO publication_reviews (
                        methodology_version, policy_digest, reviewer_name, reviewer_role,
                        decision, notes
                    ) VALUES (
                        :methodology, :digest, 'Reviewer Fictiv (demonstrație)',
                        'Data Protection Officer (fictional)', 'approved',
                        'Recorded by scripts/seed_demo.py for a local demonstration. '
                        'Not a legal or privacy review of anything.'
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"methodology": methodology, "digest": digest},
            )

    if arguments.approve_publication:
        with engine.begin() as connection:
            profile = publish_domain(connection, domains[PRIMARY_HOST])
        published = profile.registrable_domain if profile else "nothing"
    else:
        published = "nothing (run with --approve-publication)"

    engine.dispose()

    print(f"organization  {organization_id}  {ORGANIZATION_NAME}")
    for host, value in domains.items():
        print(f"domain        {value}  {host}")
    for subject, (user_id, email, name, role) in people.items():
        print(f"user          {subject:14} {name:18} {role:20} {email}")
    print(f"published     {published}")
    print()
    print("Sign in as one of the subjects above (SIEMBIOT_DEV_IDENTITY_SUBJECT), then open")
    print(f"  /organizations/{organization_id}/domains")
    return 0


def _write_assessment(
    connection: object,
    text: object,
    *,
    organization_id: UUID,
    domain_id: UUID,
    host: str,
    methodology: str,
    digest: str,
    label: str,
    when: datetime,
    overrides: dict[str, str],
    is_latest: bool,
) -> None:
    """One completed run, with a score snapshot and per-check evaluations."""
    assessment_id = identifier("assessment", label)
    results = {check: overrides.get(check, result) for check, (result, _) in EVALUATIONS.items()}

    scoring = [
        (check, results[check], pillar)
        for check, (_, pillar) in EVALUATIONS.items()
        if results[check] in {"pass", "fail", "warning"}
    ]
    factor = {"pass": 1.0, "warning": 0.5, "fail": 0.0}
    score = round(sum(factor[result] for _, result, _ in scoring) / len(scoring) * 100, 2)
    band = (
        "resilient"
        if score >= 90
        else "managed"
        if score >= 75
        else "developing"
        if score >= 55
        else "exposed"
        if score >= 30
        else "critical"
    )

    connection.execute(  # type: ignore[attr-defined]
        text(  # type: ignore[operator]
            """
            INSERT INTO assessments (
                id, organization_id, domain_id, methodology_version, state, mode,
                created_at, completed_at
            ) VALUES (
                :id, :organization_id, :domain_id, :methodology, 'completed',
                'passive_observation', :when, :when
            )
            ON CONFLICT (id) DO UPDATE SET completed_at = excluded.completed_at
            """
        ),
        {
            "id": assessment_id,
            "organization_id": organization_id,
            "domain_id": domain_id,
            "methodology": methodology,
            "when": when,
        },
    )

    for check, result, pillar in [
        (check, results[check], pillar) for check, (_, pillar) in EVALUATIONS.items()
    ]:
        connection.execute(  # type: ignore[attr-defined]
            text(  # type: ignore[operator]
                """
                INSERT INTO check_evaluations (
                    id, organization_id, assessment_id, check_id, check_version,
                    methodology_version, pillar, subject_kind, subject_identifier,
                    result, score_bearing, weight, severity, attribution_confidence,
                    source_confidence, freshness_confidence, evaluated_at
                ) VALUES (
                    :id, :organization_id, :assessment_id, :check_id, '1.0.0',
                    :methodology, :pillar, 'domain', :host, :result, :score_bearing,
                    10, :severity, 1.00, 1.00, 1.00, :when
                )
                ON CONFLICT (assessment_id, check_id, subject_identifier) DO NOTHING
                """
            ),
            {
                "id": identifier("evaluation", label, check),
                "organization_id": organization_id,
                "assessment_id": assessment_id,
                "check_id": check,
                "methodology": methodology,
                "pillar": pillar,
                "host": host,
                "result": result,
                "score_bearing": result in {"pass", "fail", "warning"},
                "severity": SEVERITIES[result],
                "when": when,
            },
        )

    coverage = round(len(scoring) / len(EVALUATIONS) * 100, 2)
    connection.execute(  # type: ignore[attr-defined]
        text(  # type: ignore[operator]
            """
            INSERT INTO score_snapshots (
                id, organization_id, assessment_id, methodology_version, is_projection,
                policy_digest, evidence_digest, uncapped_score, score, band,
                coverage_percentage, coverage_sufficient, document, computed_at
            ) VALUES (
                :id, :organization_id, :assessment_id, :methodology, false,
                :digest, :evidence, :score, :score, :band, :coverage, true,
                :document, :when
            )
            -- DO NOTHING, not DO UPDATE: score snapshots are append-only, and the
            -- trigger that enforces it refuses the second run. Caught by running this
            -- twice, which is the only way to find out whether "idempotent" was true.
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "id": identifier("snapshot", label),
            "organization_id": organization_id,
            "assessment_id": assessment_id,
            "methodology": methodology,
            "digest": digest,
            "evidence": identifier("evidence", label).hex * 2,
            "score": score,
            "band": band,
            "coverage": coverage,
            "document": json.dumps({"seeded": True, "label": label}),
            "when": when,
        },
    )
    if is_latest:
        print(f"  latest run: score {score} band {band} coverage {coverage}%")


def _write_findings(
    connection: object, text: object, *, organization_id: UUID, domain_id: UUID, when: datetime
) -> None:
    """One finding per failing or warning check, so the findings page has something real
    to render and the roadmap has something to plan against."""
    for check, (result, pillar) in EVALUATIONS.items():
        if result not in {"fail", "warning"}:
            continue
        finding_id = identifier("finding", check)
        connection.execute(  # type: ignore[attr-defined]
            text(  # type: ignore[operator]
                """
                INSERT INTO findings (
                    id, organization_id, fingerprint, check_id, check_version,
                    methodology_version, pillar, subject_kind, subject_identifier,
                    authorized_domain_id, severity, state, public_safety_class,
                    attribution_confidence, source_confidence, freshness_confidence,
                    first_seen_at, last_seen_at
                ) VALUES (
                    :id, :organization_id, :fingerprint, :check_id, '1.0.0',
                    (SELECT version FROM methodology_versions ORDER BY version DESC LIMIT 1),
                    :pillar, 'domain', :host, :domain_id, :severity, 'open',
                    'public_profile', 1.00, 1.00, 1.00, :first_seen, :when
                )
                ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at
                """
            ),
            {
                "id": finding_id,
                "organization_id": organization_id,
                "fingerprint": finding_id.hex * 2,
                "check_id": check,
                "pillar": pillar,
                "host": PRIMARY_HOST,
                "domain_id": domain_id,
                "severity": SEVERITIES[result],
                "first_seen": when - timedelta(days=30),
                "when": when,
            },
        )


def _write_maturity(
    connection: object, text: object, *, organization_id: UUID, actor: UUID
) -> None:
    for question, answer in MATURITY_ANSWERS.items():
        connection.execute(  # type: ignore[attr-defined]
            text(  # type: ignore[operator]
                """
                INSERT INTO maturity_responses (
                    organization_id, questionnaire_id, questionnaire_version,
                    question_id, answer, answered_by_user_id
                ) VALUES (
                    :organization_id, 'nis2_baseline', '1.0.0', :question, :answer, :actor
                )
                ON CONFLICT (organization_id, questionnaire_id, question_id)
                DO UPDATE SET answer = excluded.answer
                """
            ),
            {
                "organization_id": organization_id,
                "question": question,
                "answer": answer,
                "actor": actor,
            },
        )


def _write_roadmap(connection: object, text: object, *, organization_id: UUID, actor: UUID) -> None:
    """Two planned actions, one of them asserted complete while the weakness is still
    observed -- which is the disagreement the roadmap exists to surface."""
    plans = (
        ("B.dmarc_enforced", "completed", "Am publicat politica DMARC în regim de aplicare."),
        ("A.dnssec_enabled", "in_progress", "Așteptăm confirmarea de la registrar."),
    )
    for check, status, note in plans:
        connection.execute(  # type: ignore[attr-defined]
            text(  # type: ignore[operator]
                """
                INSERT INTO remediation_actions (
                    id, organization_id, finding_id, status, owner_user_id, due_at, note,
                    completed_at, created_by_user_id
                ) VALUES (
                    :id, :organization_id, :finding_id, :status, :actor,
                    now() + interval '14 days', :note,
                    CASE WHEN :status = 'completed' THEN now() ELSE NULL END, :actor
                )
                ON CONFLICT (finding_id) DO UPDATE SET status = excluded.status
                """
            ),
            {
                "id": identifier("action", check),
                "organization_id": organization_id,
                "finding_id": identifier("finding", check),
                "status": status,
                "actor": actor,
                "note": note,
            },
        )


if __name__ == "__main__":
    raise SystemExit(main())
