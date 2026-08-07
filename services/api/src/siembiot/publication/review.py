"""The interlock: nothing is published before a named person approved it.

The milestone this belongs to has one acceptance criterion that is not about code:
*counsel and privacy review is recorded before live catalog data*. That is a decision
nobody writing software gets to make on somebody else's behalf, so the software's job is
to make it impossible to skip and impossible to make anonymously.

A configuration flag would have been easier and would have been wrong. A flag has no
author, no date, and nothing to point at afterwards; somebody sets it during a
deployment and the record of who decided is a shell history on a laptop. A row has a
name, a role, a moment, and a specific methodology version and catalogue digest it
applies to -- so approving publication under one set of rules does not silently approve
it under the rules that replace them.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

APPROVED = "approved"


class ReviewMissingError(RuntimeError):
    """No approving review covers this methodology and catalogue."""


def require_approved_review(
    connection: Connection, *, methodology_version: str, policy_digest: str
) -> str:
    """The reviewer who approved publishing under exactly these rules.

    Matched on the catalogue digest as well as the version, so a catalogue edited after
    approval -- even one that keeps the same version string -- needs approving again.
    That is stricter than it sounds and deliberately so: the digest is what the reviewer
    actually read.

    Returns the reviewer's name, which callers record alongside what they publish.
    """
    row = (
        connection.execute(
            text(
                """
                SELECT reviewer_name, reviewer_role, decision
                FROM publication_reviews
                WHERE methodology_version = :methodology_version
                  AND policy_digest = :policy_digest
                ORDER BY decided_at DESC
                LIMIT 1
                """
            ),
            {"methodology_version": methodology_version, "policy_digest": policy_digest},
        )
        .mappings()
        .one_or_none()
    )

    if row is None:
        raise ReviewMissingError(
            f"publication is not approved for methodology {methodology_version} "
            f"with catalogue {policy_digest[:12]}: no review recorded"
        )
    if row["decision"] != APPROVED:
        # The most recent decision wins, so a refusal after an approval stops
        # publication without anybody having to delete the earlier row.
        raise ReviewMissingError(
            f"publication was refused for methodology {methodology_version} "
            f"by {row['reviewer_name']} ({row['reviewer_role']})"
        )
    return str(row["reviewer_name"])
