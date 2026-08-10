"""Passive observation must stay strictly smaller than authorized assessment.

The point of this mode is that it needs no ownership proof, which is only defensible
while it cannot reach anything an unauthorized party has no right to. These tests
attack that boundary rather than assuming it.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from siembiot_worker.network_safety.collection_broker import CollectionRequest
from siembiot_worker.network_safety.collection_policy import (
    PROVIDER_REDIRECT_CLASSES,
    CollectionDestination,
    OperationClass,
    authorize_collection_redirect,
    follows_provider_redirects,
    http_destination,
)
from siembiot_worker.network_safety.models import BrokerCheckpoint
from siembiot_worker.observation.mode import (
    AUTHORIZED_ONLY_OPERATION_CLASSES,
    PASSIVE_OPERATION_CLASSES,
    AssessmentMode,
    ModeError,
    allowed_operation_classes,
    assert_operation_allowed,
    is_check_available,
    mode_coverage,
)
from siembiot_worker.observation.runtime import KillSwitch, ModeEnforcingPolicy
from siembiot_worker.policy.catalog import load_catalog
from siembiot_worker.policy.evidence import Subject, SubjectKind

CATALOG = load_catalog()
HOST = "example.test"


def request(operation_class: OperationClass) -> CollectionRequest:
    return CollectionRequest(uuid4(), uuid4(), None, operation_class, HOST, (HOST,))


def policy(mode: AssessmentMode = AssessmentMode.PASSIVE_OBSERVATION) -> ModeEnforcingPolicy:
    return ModeEnforcingPolicy(mode, sleeper=lambda _: None)


# -- the allowlist -----------------------------------------------------------


def test_the_two_modes_partition_every_operation_class() -> None:
    assert PASSIVE_OPERATION_CLASSES.isdisjoint(AUTHORIZED_ONLY_OPERATION_CLASSES)
    assert (PASSIVE_OPERATION_CLASSES | AUTHORIZED_ONLY_OPERATION_CLASSES) == set(OperationClass)


def test_ownership_verification_is_never_passive() -> None:
    assert OperationClass.HTTPS_VERIFICATION in AUTHORIZED_ONLY_OPERATION_CLASSES
    assert OperationClass.HTTPS_VERIFICATION not in allowed_operation_classes(
        AssessmentMode.PASSIVE_OBSERVATION
    )
    with pytest.raises(ModeError, match="requires_authorization"):
        assert_operation_allowed(
            AssessmentMode.PASSIVE_OBSERVATION, OperationClass.HTTPS_VERIFICATION
        )


def test_authorized_mode_is_a_superset_never_a_different_set() -> None:
    passive = allowed_operation_classes(AssessmentMode.PASSIVE_OBSERVATION)
    authorized = allowed_operation_classes(AssessmentMode.AUTHORIZED_ASSESSMENT)
    assert passive < authorized


@pytest.mark.parametrize("operation_class", sorted(AUTHORIZED_ONLY_OPERATION_CLASSES))
def test_the_policy_refuses_an_authorized_only_operation_at_every_checkpoint(
    operation_class: OperationClass,
) -> None:
    enforcing = policy()
    for checkpoint in BrokerCheckpoint:
        decision = enforcing.authorize(request(operation_class), checkpoint, HOST)
        assert decision.allowed is False
        assert decision.reason_code == "operation_class_requires_authorization"


@pytest.mark.parametrize("operation_class", sorted(PASSIVE_OPERATION_CLASSES))
def test_the_policy_permits_every_passive_operation(operation_class: OperationClass) -> None:
    decision = policy().authorize(
        request(operation_class), BrokerCheckpoint.BEFORE_RESOLUTION, HOST
    )
    assert decision.allowed is True


def test_an_authorized_run_may_perform_ownership_verification() -> None:
    decision = policy(AssessmentMode.AUTHORIZED_ASSESSMENT).authorize(
        request(OperationClass.HTTPS_VERIFICATION), BrokerCheckpoint.BEFORE_RESOLUTION, HOST
    )
    assert decision.allowed is True


# -- the kill switch ---------------------------------------------------------


def test_the_kill_switch_stops_observation_immediately() -> None:
    switch = KillSwitch()
    enforcing = ModeEnforcingPolicy(
        AssessmentMode.PASSIVE_OBSERVATION, kill_switch=switch, sleeper=lambda _: None
    )
    assert enforcing.authorize(
        request(OperationClass.DNS_QUERY), BrokerCheckpoint.BEFORE_RESOLUTION, HOST
    ).allowed
    switch.halt()
    denied = enforcing.authorize(
        request(OperationClass.DNS_QUERY), BrokerCheckpoint.BEFORE_RESOLUTION, HOST
    )
    assert denied.allowed is False
    assert denied.reason_code == "emergency_control_active"


def test_the_kill_switch_outranks_an_otherwise_permitted_operation() -> None:
    switch = KillSwitch(active=True)
    enforcing = ModeEnforcingPolicy(
        AssessmentMode.AUTHORIZED_ASSESSMENT, kill_switch=switch, sleeper=lambda _: None
    )
    for operation_class in OperationClass:
        decision = enforcing.authorize(
            request(operation_class), BrokerCheckpoint.BEFORE_CONNECT, HOST
        )
        assert decision.allowed is False


# -- provider redirects ------------------------------------------------------


def test_only_provider_lookups_may_redirect_to_an_unknown_host() -> None:
    assert PROVIDER_REDIRECT_CLASSES == {OperationClass.RDAP_QUERY, OperationClass.CT_QUERY}
    assert follows_provider_redirects(OperationClass.RDAP_QUERY)
    assert not follows_provider_redirects(OperationClass.HTTP_SURFACE)
    assert not follows_provider_redirects(OperationClass.EMAIL_POLICY_FETCH)
    assert not follows_provider_redirects(OperationClass.HTTPS_VERIFICATION)


def test_a_target_owned_fetch_still_refuses_an_unauthorized_redirect() -> None:
    destination = http_destination(OperationClass.HTTP_SURFACE, HOST)
    with pytest.raises(Exception, match="redirect_not_authorized"):
        authorize_collection_redirect(
            destination, "https://elsewhere.test/", authorized_hosts=frozenset({HOST})
        )


def test_a_provider_redirect_still_obeys_scheme_and_port_policy() -> None:
    destination = CollectionDestination(
        OperationClass.RDAP_QUERY, "https", "rdap.example.test", 443, "/domain/x"
    )
    for location in ("http://registry.test/domain/x", "https://registry.test:8443/domain/x"):
        with pytest.raises(Exception):
            authorize_collection_redirect(
                destination, location, authorized_hosts=frozenset({"rdap.example.test"})
            )


def test_a_provider_redirect_to_a_public_registry_is_permitted() -> None:
    destination = CollectionDestination(
        OperationClass.RDAP_QUERY, "https", "rdap.example.test", 443, "/domain/x"
    )
    followed = authorize_collection_redirect(
        destination,
        "https://registry.example.test/com/v1/domain/x",
        authorized_hosts=frozenset({"rdap.example.test"}),
    )
    assert followed.host == "registry.example.test"


# -- catalog availability ----------------------------------------------------


def test_every_methodology_1_0_check_is_passively_collectable() -> None:
    """The version the public observatory publishes under.

    Everything in 1.0.0 reads what a domain already publishes, which is what makes an
    observation of an unenrolled domain lawful. This has to stay true of that version
    however far later ones go.
    """
    from siembiot_worker.policy.catalog import load_catalog

    original = load_catalog(version="1.0.0")
    coverage = mode_coverage(original, AssessmentMode.PASSIVE_OBSERVATION)
    assert coverage.complete
    assert len(coverage.available_check_ids) == len(original.checks)


def test_the_active_checks_are_withheld_from_passive_mode() -> None:
    """This used to synthesise an active check because none existed yet.

    Methodology 1.1.0 added three, so the test uses the real ones: a synthesised check
    proves the function works, and these prove the catalogue is classified correctly.
    """
    withheld = [
        check
        for check in CATALOG.checks
        if not is_check_available(check, AssessmentMode.PASSIVE_OBSERVATION)
    ]
    assert {check.check_id for check in withheld} == {
        "D.remote_access_exposed",
        "D.database_exposed",
        "D.management_interface_exposed",
    }
    for check in withheld:
        assert is_check_available(check, AssessmentMode.AUTHORIZED_ASSESSMENT) is True


def test_a_withheld_check_is_not_applicable_rather_than_a_pass() -> None:
    """A thin passive run must not look like a clean authorized one."""
    from dataclasses import replace

    from siembiot_worker.observation.pipeline import withhold_unavailable_checks
    from siembiot_worker.policy.evidence import CheckEvaluation, Confidence

    check = CATALOG.checks[0]
    active_catalog = replace(
        CATALOG, checks=(replace(check, collection_mode="active"), *CATALOG.checks[1:])
    )
    evaluation = CheckEvaluation(
        evaluation_id=uuid4(),
        organization_id=uuid4(),
        assessment_id=uuid4(),
        check_id=check.check_id,
        check_version=check.version,
        methodology_version=CATALOG.methodology.version,
        pillar=check.pillar,
        subject=Subject(SubjectKind.DOMAIN, HOST),
        result="pass",
        weight=check.weight,
        severity=str(check.severity),
        confidence=Confidence(1.0, 1.0, 1.0),
    )
    withheld = withhold_unavailable_checks(
        active_catalog, (evaluation,), AssessmentMode.PASSIVE_OBSERVATION
    )
    assert withheld[0].result == "not_applicable"
    assert withheld[0].reason_code == "requires_authorized_assessment"
    assert withheld[0].score_bearing is False
