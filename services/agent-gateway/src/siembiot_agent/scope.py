"""What one run may look at, and the refusal of everything else.

The scope is built by the platform from an authorization that already passed the
centralized authorization service. The model never proposes it, extends it or edits it:
there is no message it can send that changes what is in here.

Every tool call is checked against it. That check is the reason a compromised or
manipulated model cannot reach another institution's data -- not the prompt, not the
tool descriptions, and not the model's own restraint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

OUT_OF_SCOPE_SUBJECT = "subject_not_in_scope"
CROSS_TENANT = "evidence_belongs_to_another_organization"
SCOPE_EXPIRED = "scope_expired"
UNKNOWN_TOOL = "tool_not_permitted"

#: The complete set of tools. Every one reads; none writes, reaches the network, executes
#: anything, or accepts a query.
#:
#: A closed enum rather than a registry with a deny-list: with a deny-list, the safety of
#: the system depends on somebody having thought of every dangerous capability in advance,
#: and the first one nobody thought of is available by default.
PERMITTED_TOOLS: frozenset[str] = frozenset(
    {
        "read_findings",
        "read_evaluations",
        "read_observation",
        "read_remediation_template",
        "read_knowledge_base",
    }
)


@dataclass(frozen=True)
class AssessmentScope:
    run_id: UUID
    organization_id: UUID
    assessment_id: UUID
    subjects: frozenset[str]
    expires_at: datetime

    def refusal_for(
        self, tool: str, subject: str | None = None, now: datetime | None = None
    ) -> str | None:
        """Why this call is refused, or None if it is allowed.

        Checked in this order on purpose. Expiry first, because an expired scope permits
        nothing and the other questions are then irrelevant; the tool second, because an
        unnamed tool is refused whatever it was aimed at.
        """
        if (now or datetime.now(UTC)) >= self.expires_at:
            return SCOPE_EXPIRED
        if tool not in PERMITTED_TOOLS:
            return UNKNOWN_TOOL
        if subject is not None and subject not in self.subjects:
            return OUT_OF_SCOPE_SUBJECT
        return None
