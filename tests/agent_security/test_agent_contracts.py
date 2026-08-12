"""The gateway's real output must validate against the published agent schemas.

Not shape tests: genuine gateway output is fed through the contracts, so the two cannot
drift. A schema that describes a document the code no longer produces is worse than no
schema, because a reviewer reads it and believes it.

The negative cases matter more than the positive ones here. Each asserts that a dangerous
document is *unrepresentable* rather than merely refused at runtime — a shell tool, an
unsupported claim, a trusted tool result, a narrative carrying a score.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "packages" / "contracts" / "jsonschema" / "agent" / "v1"

sys.path.insert(0, str(ROOT / "services" / "agent-gateway" / "src"))

from siembiot_agent.gateway import run_analysis  # noqa: E402
from siembiot_agent.provider import Completion  # noqa: E402
from siembiot_agent.scope import AssessmentScope  # noqa: E402

EVIDENCE = "11111111-1111-4111-8111-111111111111"

#: Every contract the plan names for this milestone. Three of them -- observation,
#: evaluation and finding -- are the Milestone 4 evidence contracts and live under
#: `evidence/v1`, because the agent reads the same documents the deterministic engine
#: writes rather than a parallel set that could disagree with them.
AGENT_SCHEMAS = (
    "assessment-scope",
    "execution-plan",
    "tool-call-request",
    "tool-call-result",
    "report-narrative",
    "remediation-action",
    "agent-run-audit",
)
SHARED_EVIDENCE_SCHEMAS = ("normalized-observation", "check-evaluation", "finding")


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class ScriptedProvider:
    name = "scripted"
    model = "test"

    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def complete(self, instructions: str, data: dict[str, object]) -> Completion:
        del instructions, data
        return Completion(self.payload, tokens_used=5)


# -- the contracts exist and are well formed --------------------------------------------


@pytest.mark.parametrize("name", AGENT_SCHEMAS)
def test_each_agent_contract_is_a_valid_schema(name: str) -> None:
    assert validator(name)


@pytest.mark.parametrize("name", SHARED_EVIDENCE_SCHEMAS)
def test_the_shared_evidence_contracts_exist(name: str) -> None:
    """The agent reads what the deterministic engine wrote. A separate agent-side copy
    of these could drift from the originals and describe evidence that never existed."""
    path = ROOT / "packages" / "contracts" / "jsonschema" / "evidence" / "v1" / f"{name}.json"
    assert path.exists(), f"{name} is missing"


@pytest.mark.parametrize("name", AGENT_SCHEMAS)
def test_every_agent_contract_refuses_unknown_fields(name: str) -> None:
    """Strict by construction. A model that invents a field produces an invalid document
    rather than one that is silently accepted with something extra in it."""
    schema = json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8"))
    assert schema.get("additionalProperties") is False, name


# -- the dangerous documents are unrepresentable -----------------------------------------


@pytest.mark.parametrize("tool", ["shell", "sql", "http_fetch", "exec", "browse"])
def test_a_dangerous_tool_cannot_be_expressed_in_a_request(tool: str) -> None:
    request = {
        "contract_version": "v1",
        "run_id": str(uuid4()),
        "call_id": str(uuid4()),
        "tool": tool,
        "arguments": {},
    }

    assert not validator("tool-call-request").is_valid(request)


def test_a_tool_result_cannot_claim_to_be_trusted() -> None:
    """`untrusted` is a const. There is no valid result document in which tool output is
    trusted input."""
    result = {
        "contract_version": "v1",
        "run_id": str(uuid4()),
        "call_id": str(uuid4()),
        "status": "ok",
        "untrusted": False,
    }

    assert not validator("tool-call-result").is_valid(result)


def test_a_claim_without_support_is_not_a_valid_narrative() -> None:
    """Enforced in the schema as well as in the validator, so an unsupported claim
    cannot even be serialized on the way to one."""
    narrative = {
        "contract_version": "v1",
        "run_id": str(uuid4()),
        "claims": [{"text": "Everything is fine.", "kind": "measured", "support": []}],
    }

    assert not validator("report-narrative").is_valid(narrative)


def test_a_narrative_has_nowhere_to_put_a_score() -> None:
    narrative = {
        "contract_version": "v1",
        "run_id": str(uuid4()),
        "score": 42,
        "claims": [],
    }

    assert not validator("report-narrative").is_valid(narrative)


def test_a_claim_kind_outside_the_three_is_refused() -> None:
    """Measured, inferred and recommended are shown differently in the interface. A
    fourth kind would render as something the reader has no way to weigh."""
    narrative = {
        "contract_version": "v1",
        "run_id": str(uuid4()),
        "claims": [
            {
                "text": "x",
                "kind": "certain",
                "support": [{"type": "evidence", "id": EVIDENCE}],
            }
        ],
    }

    assert not validator("report-narrative").is_valid(narrative)


# -- real output validates ----------------------------------------------------------------


def test_the_gateways_audit_record_validates() -> None:
    """Genuine output from a real run, through the published contract."""
    provider = ScriptedProvider(
        {
            "claims": [
                {
                    "text": "DMARC is not enforced.",
                    "kind": "measured",
                    "support": [{"type": "evidence", "id": EVIDENCE}],
                }
            ]
        }
    )

    result = run_analysis(
        scope=AssessmentScope(
            run_id=uuid4(),
            organization_id=uuid4(),
            assessment_id=uuid4(),
            subjects=frozenset({"primaria-exemplu.ro"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        ),
        provider=provider,
        readers={},
        evidence={"id": EVIDENCE},
    )

    validator("agent-run-audit").validate(result.audit.as_document())
    assert result.audit.claims_accepted == 1


def test_a_disabled_run_still_produces_a_valid_audit_record() -> None:
    """The outcome nobody thinks to validate, and the one that happens every time in a
    default deployment."""
    from siembiot_agent.provider import DisabledProvider

    result = run_analysis(
        scope=AssessmentScope(
            run_id=uuid4(),
            organization_id=uuid4(),
            assessment_id=uuid4(),
            subjects=frozenset({"primaria-exemplu.ro"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        ),
        provider=DisabledProvider(),
        readers={},
        evidence={},
    )

    validator("agent-run-audit").validate(result.audit.as_document())
    assert result.audit.outcome == "provider_unavailable"
