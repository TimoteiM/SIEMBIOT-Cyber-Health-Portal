"""DKIM selectors an organization declares for its own domain.

DKIM is the one check in the e-mail pillar that cannot be answered by looking. A selector
is an arbitrary label chosen by whoever set up the signing -- `s1`, `google`, `mail`,
`k1-2024` -- and it lives at `<selector>._domainkey.<domain>`. There is no record that
lists them, so the only passive options are to guess names or to be told. Guessing is
what this platform refuses to do everywhere else, so it asks.

Stored on the domain rather than in a table of its own: a selector is a property of the
domain the way its name is, there is no history worth keeping about it, and a separate
table would need its own policies to say the same thing the domain's already say.

Empty is the ordinary state and not a defect. With nothing declared the collector reports
`not_applicable`, the check is excluded from scoring entirely, and coverage is untouched --
the same treatment as a reputation provider nobody configured. An institution that never
fills this in is not penalised for it; it simply has one fewer check answered.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0024_declared_dkim_selectors"
down_revision: str | Sequence[str] | None = "0023_backup_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE domains
            ADD COLUMN declared_dkim_selectors text[] NOT NULL DEFAULT '{}'::text[];

        -- A selector becomes a DNS label, so it is bounded here as well as in the API.
        -- The constraint is what holds when somebody writes to the table by another
        -- route, and a label longer than 63 octets cannot be queried anyway.
        --
        -- Expressed over the joined array because a check constraint may not contain a
        -- subquery, so `unnest` is unavailable: the regex matches one selector, then any
        -- number of comma-separated further ones. A comma cannot appear in a selector,
        -- which is what makes the join unambiguous.
        --
        -- Dots are permitted inside a selector. RFC 6376 defines one as
        -- `sub-domain *("." sub-domain)`, so `a.b` is legal and refusing it would stop an
        -- institution declaring the selector it actually uses -- the failure that matters
        -- here, since a selector nobody can enter leaves the check unanswerable forever.
        ALTER TABLE domains
            ADD CONSTRAINT declared_dkim_selectors_are_labels CHECK (
                array_length(declared_dkim_selectors, 1) IS NULL
                OR (
                    array_length(declared_dkim_selectors, 1) <= 10
                    AND array_to_string(declared_dkim_selectors, ',') ~
                        '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                        '(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*'
                        '(,[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                        '(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)*$'
                )
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE domains DROP CONSTRAINT IF EXISTS declared_dkim_selectors_are_labels;
        ALTER TABLE domains DROP COLUMN IF EXISTS declared_dkim_selectors;
        """
    )
