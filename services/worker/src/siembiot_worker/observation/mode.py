"""Assessment modes.

The product has always had two lawful paths to a domain, and this module makes the
difference explicit rather than implicit:

**Passive observation** is what the Public Observatory does. It looks at public data —
DNS, RDAP, Certificate Transparency — and reads a public web page the way any visitor
does. It needs no ownership proof because it asks nothing of the target that the target
does not already publish to everyone.

**Authorized assessment** is everything else: anything that probes beyond what a normal
visitor sees. It requires verified domain control, a signed scope manifest and recorded
consent.

Passive mode is not "authorized mode with the checks turned off". It is a strictly
smaller set of operations, enforced here by an allowlist, so no future check can quietly
widen what an unauthorized run may do.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from siembiot_worker.network_safety.collection_policy import OperationClass
from siembiot_worker.policy.catalog import Check, PolicyCatalog


class AssessmentMode(StrEnum):
    PASSIVE_OBSERVATION = "passive_observation"
    AUTHORIZED_ASSESSMENT = "authorized_assessment"


#: Operations that observe only what the target already publishes publicly.
#:
#: A DNS query asks a public resolver. RDAP and CT read public registries. An HTTP GET
#: of the site root and a TLS handshake on 443 are exactly what a browser does when
#: someone visits the site. None of them asks the target for anything a member of the
#: public could not already request.
PASSIVE_OPERATION_CLASSES: frozenset[OperationClass] = frozenset(
    {
        OperationClass.DNS_QUERY,
        OperationClass.RDAP_QUERY,
        OperationClass.CT_QUERY,
        OperationClass.HTTP_SURFACE,
        OperationClass.EMAIL_POLICY_FETCH,
        OperationClass.TLS_INSPECTION,
    }
)

#: Operations that require verified control and a signed authorization. Listed
#: explicitly so the two sets are visibly exhaustive rather than "everything else".
AUTHORIZED_ONLY_OPERATION_CLASSES: frozenset[OperationClass] = frozenset(
    {OperationClass.HTTPS_VERIFICATION}
)


class ModeError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def allowed_operation_classes(mode: AssessmentMode) -> frozenset[OperationClass]:
    if mode is AssessmentMode.PASSIVE_OBSERVATION:
        return PASSIVE_OPERATION_CLASSES
    return PASSIVE_OPERATION_CLASSES | AUTHORIZED_ONLY_OPERATION_CLASSES


def assert_operation_allowed(mode: AssessmentMode, operation_class: OperationClass) -> None:
    if operation_class not in allowed_operation_classes(mode):
        raise ModeError("operation_class_requires_authorization")


def is_check_available(check: Check, mode: AssessmentMode) -> bool:
    """Whether a catalog check can be evaluated in this mode.

    A check is available passively when it is collected passively or derived from other
    observations. Anything else is withheld and reported as not applicable, so an
    unauthorized run never silently produces a thinner score that looks like a real one.
    """
    if mode is AssessmentMode.AUTHORIZED_ASSESSMENT:
        return True
    return check.collection_mode in {"passive", "derived"}


@dataclass(frozen=True)
class ModeCoverage:
    """What a mode can and cannot see, so the limitation is stated rather than implied."""

    mode: AssessmentMode
    available_check_ids: tuple[str, ...]
    withheld_check_ids: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.withheld_check_ids


def mode_coverage(catalog: PolicyCatalog, mode: AssessmentMode) -> ModeCoverage:
    available = tuple(check.check_id for check in catalog.checks if is_check_available(check, mode))
    withheld = tuple(
        check.check_id for check in catalog.checks if not is_check_available(check, mode)
    )
    return ModeCoverage(mode, available, withheld)
