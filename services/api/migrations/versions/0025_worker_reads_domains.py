"""Let the worker read the domain row of the tenant it is scoped to.

Declaring DKIM selectors stored them on the domain, and the worker could not see them:
`domains` had only the tenant policy, which requires an active membership, and the worker
is a service role with none. So the declaration was written, stored, and silently ignored
-- the run reported `not_applicable` exactly as though nothing had been declared, which is
the worst shape a failure can take here because it is indistinguishable from the ordinary
case.

Found by declaring selectors through the interface and watching the next assessment ignore
them. No test caught it: they exercise the API as a member and the collector with
selectors handed to it directly, and nothing drove the path the worker actually takes.

The policy mirrors the one every other table the worker reads already has --
`asset_candidates_worker_select`, `normalized_observations_worker_select` -- and is scoped
by `app_is_worker_for`, so it grants the worker nothing outside the organization its
connection is bound to. It is not a widening of what the worker can reach: it already
reads that tenant's observations, candidates and assessments, and receives the domain's
own host name as a task argument.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0025_worker_reads_domains"
down_revision: str | Sequence[str] | None = "0024_declared_dkim_selectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY domains_worker_select ON domains
            FOR SELECT USING (app_is_worker_for(organization_id));
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS domains_worker_select ON domains;")
