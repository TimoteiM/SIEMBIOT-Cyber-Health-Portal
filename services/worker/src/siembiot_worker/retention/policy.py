"""How long each kind of data is kept, and why.

Evidence accumulated indefinitely because nothing ever removed it. That is a privacy
problem before it is a storage one: this platform holds observations about public
institutions -- what their servers run, which ports answer, who operates their networks
-- and keeping that forever is a choice nobody made deliberately.

The schedule is expressed as a table because the dangerous failure is silence. A table
added next year that nobody classifies would simply grow, and nothing would say so. So
**every table is named here**, including the ones that are never swept, and a test fails
when one is missing. "Not listed" is not a retention decision.

Two rules are absolute:

**Audit is never swept.** Its rows are chained by hash, so deleting from the middle
breaks verification of everything after it -- and an accountability record that can be
aged out is not one. If audit ever needs bounding, that is a legal decision with its own
migration, not a periodic job.

**Conclusions outlive the evidence for them.** An institution's scores and findings are
its own record and stay; the observations underneath them expire. This costs something
real and the code says so rather than hiding it: once evidence is gone the score cannot
be recomputed, so the snapshot is stamped `evidence_erased_at` and every report drawn
from it tells the reader that the workings are no longer there.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum


class RetentionClass(StrEnum):
    #: Observations and the operational record of touching somebody else's network.
    #: Bulky, privacy-sensitive, and only needed while it is fresh enough to act on.
    EVIDENCE = "evidence"
    #: Queue and step bookkeeping. Useful for a few weeks of debugging, useless after.
    OPERATIONAL = "operational"
    #: Tokens, challenges, idempotency keys. Dead within hours of being issued.
    EPHEMERAL = "ephemeral"
    #: What the organisation is entitled to keep: its scores, findings, answers,
    #: decisions. Not swept on a timer -- removed when the organisation is removed.
    RECORD = "record"
    #: The accountability trail. Never swept; see the module docstring.
    ACCOUNTABILITY = "accountability"
    #: Identity, tenancy and catalogues. Lifetime follows the thing they describe, not
    #: the calendar.
    REFERENCE = "reference"


@dataclass(frozen=True)
class TableRetention:
    table: str
    retention_class: RetentionClass
    #: The column deciding a row's age. `None` where the class is never swept, which is
    #: also what stops a sweep being written for one of those by accident.
    age_column: str | None = None
    period: timedelta | None = None

    @property
    def is_swept(self) -> bool:
        return self.period is not None and self.age_column is not None


#: Ninety days of evidence. Long enough that a quarterly reassessment can be compared
#: with the one before it, short enough that a breach of this database does not hand
#: somebody a multi-year map of every institution's infrastructure.
EVIDENCE_PERIOD = timedelta(days=90)

#: Enough to investigate an incident from a fortnight ago without keeping a permanent
#: record of every retry.
OPERATIONAL_PERIOD = timedelta(days=30)

#: Well past any legitimate use. A spent report grant or an answered challenge is dead
#: immediately; a day of slack costs nothing and avoids racing a slow client.
EPHEMERAL_PERIOD = timedelta(days=1)


def _swept(table: str, klass: RetentionClass, column: str, period: timedelta) -> TableRetention:
    return TableRetention(table, klass, column, period)


def _kept(table: str, klass: RetentionClass) -> TableRetention:
    return TableRetention(table, klass)


#: Every table, classified. Ordered so that rows referencing others are removed first;
#: the sweep relies on this rather than on cascade, because a cascade from an evidence
#: table into a record table would delete a finding to save an observation.
RETENTION_SCHEDULE: tuple[TableRetention, ...] = (
    # -- evidence -------------------------------------------------------------------
    _swept("normalized_observations", RetentionClass.EVIDENCE, "collected_at", EVIDENCE_PERIOD),
    # What we did to somebody else's network, and when. Evidence about our own conduct
    # rather than about them -- but it names their hosts, so it ages with the rest.
    _swept("network_operations", RetentionClass.EVIDENCE, "created_at", EVIDENCE_PERIOD),
    _swept("scope_manifests", RetentionClass.EVIDENCE, "created_at", EVIDENCE_PERIOD),
    # -- operational ----------------------------------------------------------------
    _swept(
        "assessment_step_attempts", RetentionClass.OPERATIONAL, "started_at", OPERATIONAL_PERIOD
    ),
    # -- ephemeral ------------------------------------------------------------------
    #
    # Aged from `expires_at`, never from `created_at`. A challenge is a live thing until
    # it expires and a domain proof can legitimately sit unanswered for weeks; ageing
    # these from creation would delete the token out from under somebody who was part
    # way through publishing a DNS record, and the failure would look like our
    # verification being broken.
    _swept("report_grants", RetentionClass.EPHEMERAL, "expires_at", EPHEMERAL_PERIOD),
    # Operational rather than ephemeral, and the one entry here where deleting too early
    # is a correctness bug rather than lost information: an idempotency key is what stops
    # a redelivered message running a step twice. Thirty days is far longer than any run,
    # so a key only ever disappears once nothing could still be retrying against it.
    _swept(
        "workflow_idempotency_keys",
        RetentionClass.OPERATIONAL,
        "recorded_at",
        OPERATIONAL_PERIOD,
    ),
    # One row per adapter per day, upserted. Swept on the operational period rather
    # than kept: Prometheus already stores the time series, and this table exists to hand
    # today's counters to the exporter. A year of daily rows here would be a time series
    # nobody queries from SQL.
    _swept(
        "provider_quota_snapshots",
        RetentionClass.OPERATIONAL,
        "captured_at",
        OPERATIONAL_PERIOD,
    ),
    # -- the organisation's own record ----------------------------------------------
    #
    # Kept until the organisation itself is removed. Sweeping any of these on a timer
    # would delete somebody's history of their own security posture to save disk.
    _kept("assessments", RetentionClass.RECORD),
    _kept("assessment_steps", RetentionClass.RECORD),
    _kept("score_snapshots", RetentionClass.RECORD),
    _kept("check_evaluations", RetentionClass.RECORD),
    _kept("findings", RetentionClass.RECORD),
    _kept("finding_history", RetentionClass.RECORD),
    _kept("finding_suppressions", RetentionClass.RECORD),
    _kept("maturity_responses", RetentionClass.RECORD),
    _kept("maturity_response_history", RetentionClass.RECORD),
    _kept("remediation_actions", RetentionClass.RECORD),
    _kept("remediation_action_history", RetentionClass.RECORD),
    _kept("asset_candidates", RetentionClass.RECORD),
    _kept("asset_candidate_decisions", RetentionClass.RECORD),
    _kept("publication_consents", RetentionClass.RECORD),
    _kept("publication_reviews", RetentionClass.RECORD),
    _kept("publication_takedowns", RetentionClass.RECORD),
    _kept("assessment_schedules", RetentionClass.RECORD),
    _kept("emergency_controls", RetentionClass.RECORD),
    # -- accountability --------------------------------------------------------------
    _kept("audit_events", RetentionClass.ACCOUNTABILITY),
    # The record of what retention itself removed. Kept for the same reason as the rest
    # of this group: deletion of somebody's data is an act that may have to be accounted
    # for, and a housekeeping job that tidied away the evidence of its own housekeeping
    # would leave nobody able to answer "what did you delete, and when".
    _kept("retention_runs", RetentionClass.ACCOUNTABILITY),
    _kept("domain_verification_events", RetentionClass.ACCOUNTABILITY),
    # Challenges look ephemeral -- a token digest with an expiry -- and were classified
    # that way until a sweep against real data hit the foreign key: a verification event
    # references the challenge it verified, and that event is accountability data that
    # never goes. Deleting the challenge would leave the record of a domain proof
    # pointing at nothing, which is the same as not having the record.
    #
    # So a challenge is part of the verification trail rather than a leftover token. What
    # accumulates is one small row per enrolment attempt, holding a digest and a domain
    # name -- no secret, since the token itself was never stored.
    _kept("domain_challenges", RetentionClass.ACCOUNTABILITY),
    # Who was given access to whose data, and when. Deleting a lapsed grant would erase
    # the record that platform staff once held it, which is the only reason it exists.
    _kept("support_access_grants", RetentionClass.ACCOUNTABILITY),
    # A signed statement that somebody permitted us to probe their systems. It outlives
    # its own expiry: the question later is not "may we?" but "were we allowed to?".
    _kept("assessment_authorizations", RetentionClass.ACCOUNTABILITY),
    _kept("authorization_targets", RetentionClass.ACCOUNTABILITY),
    # -- reference -------------------------------------------------------------------
    _kept("organizations", RetentionClass.REFERENCE),
    _kept("users", RetentionClass.REFERENCE),
    _kept("memberships", RetentionClass.REFERENCE),
    _kept("invitations", RetentionClass.REFERENCE),
    _kept("domains", RetentionClass.REFERENCE),
    _kept("methodology_versions", RetentionClass.REFERENCE),
    _kept("alembic_version", RetentionClass.REFERENCE),
)

SWEPT_TABLES: tuple[TableRetention, ...] = tuple(
    entry for entry in RETENTION_SCHEDULE if entry.is_swept
)


def classified_tables() -> frozenset[str]:
    return frozenset(entry.table for entry in RETENTION_SCHEDULE)
