from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, text


class LeastPrivilegeError(RuntimeError):
    """The API is connected as a role that row-level security does not apply to."""


#: How many connections one API process keeps, and how many more it may open under a
#: burst.
#:
#: Chosen rather than inherited. SQLAlchemy defaults to 5 + 10, and a load test found the
#: API saturating at that ceiling: throughput fell from 102 to 83 reads a second between
#: 8 and 24 concurrent clients while latency tripled, because nine of them were queueing
#: for a connection rather than doing anything.
#:
#: The number is bounded from the other end too, and that is the more important
#: constraint: PostgreSQL accepts `max_connections` in total, and every API replica
#: multiplies whatever is set here. The arithmetic a deployment has to satisfy is
#:
#:     replicas x (POOL_SIZE + MAX_OVERFLOW) + workers + scheduler + retention
#:         < max_connections
#:
#: With the defaults below and Postgres's own default of 100, that permits four replicas
#: with room to spare. Raising these without raising `max_connections` moves the failure
#: from "slow under load" to "the database refuses connections", which is worse and
#: arrives without warning.
POOL_SIZE = 10
MAX_OVERFLOW = 5

#: How long a request waits for a connection before giving up.
#:
#: SQLAlchemy waits 30 seconds. A caller has almost always stopped listening by then, so
#: the wait costs a connection slot and returns something nobody reads. Ten seconds is
#: long enough to ride out a burst and short enough that a saturated pool reports itself
#: as an error somebody can see, rather than as a service that has become mysteriously
#: slow.
POOL_TIMEOUT_SECONDS = 10


class Database:
    def __init__(
        self,
        url: str,
        connect_timeout_seconds: int = 10,
        pool_size: int = POOL_SIZE,
        max_overflow: int = MAX_OVERFLOW,
    ) -> None:
        # A bounded connect timeout so a misconfigured deployment fails in seconds
        # rather than minutes. Startup verifies the connected role, and without this a
        # wrong host makes the API hang -- which reads as a broken service rather than
        # as the configuration mistake it is.
        self.engine: Engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=POOL_TIMEOUT_SECONDS,
            # Recycled well inside any sensible idle timeout on the database side, so a
            # connection the server has already closed is never handed to a request.
            pool_recycle=1800,
            connect_args={"connect_timeout": connect_timeout_seconds},
        )

    def verify_least_privilege(self) -> None:
        """Refuse to serve as a role that row-level security cannot constrain.

        Superusers and `BYPASSRLS` roles ignore every policy, including ones declared
        `FORCE ROW LEVEL SECURITY`. Connecting as one does not fail, warn, or degrade:
        every query keeps working and every tenant boundary quietly disappears. The
        only signal is data that should not be there, which is precisely the thing
        nobody notices until it is someone else's data.

        So this is checked against the live connection rather than against the
        configured URL: the URL is a claim about which role we are, and `current_user`
        is the fact.
        """
        with self.engine.begin() as connection:
            role = connection.execute(
                text(
                    "SELECT current_user, rolsuper, rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one()
        name, is_superuser, bypasses_rls = role
        if is_superuser or bypasses_rls:
            raise LeastPrivilegeError(
                f"The API is connected as '{name}', which bypasses row-level security "
                f"(superuser={is_superuser}, bypassrls={bypasses_rls}). Tenant isolation "
                "would not be enforced. Set SIEMBIOT_APP_DATABASE_URL to the "
                "siembiot_app role; SIEMBIOT_DATABASE_URL is for migrations only."
            )

    def verify_cannot_reach_tenant_data(self) -> None:
        """Refuse to serve public routes from a connection that can see tenant tables.

        The counterpart of `verify_least_privilege`, and it fails the same way if it is
        missing: nothing errors, every public query keeps working, and the schema
        separation that the whole publication design rests on becomes decorative.

        What is checked is the *capability*, not the role name and not the configured
        URL. A role called `siembiot_public` that somebody granted USAGE to last month
        is the failure this exists to catch, and its name would not have changed.
        """
        with self.engine.begin() as connection:
            name, reaches_tenant_schema = connection.execute(
                text("SELECT current_user, has_schema_privilege(current_user, 'public', 'USAGE')")
            ).one()
        if reaches_tenant_schema:
            raise LeastPrivilegeError(
                f"Public routes are connected as '{name}', which has USAGE on the schema "
                "holding tenant data. Published pages would be served by a connection "
                "that can reach private tables. Set SIEMBIOT_PUBLIC_DATABASE_URL to the "
                "siembiot_public role."
            )

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        with self.engine.begin() as connection:
            yield connection

    @contextmanager
    def tenant_connection(self, user_id: UUID, organization_id: UUID) -> Iterator[Connection]:
        with self.engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.user_id', :user_id, true)"),
                {"user_id": str(user_id)},
            )
            connection.execute(
                text("SELECT set_config('app.organization_id', :organization_id, true)"),
                {"organization_id": str(organization_id)},
            )
            yield connection

    @contextmanager
    def user_connection(self, user_id: UUID) -> Iterator[Connection]:
        with self.engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.user_id', :user_id, true)"),
                {"user_id": str(user_id)},
            )
            yield connection

    def is_reachable(self) -> bool:
        """Whether a query can be executed right now.

        Swallows the exception on purpose: the caller is a readiness probe, and the
        useful answer is a boolean an orchestrator can act on. The reason belongs in
        the logs, which the connection failure already writes.
        """
        from sqlalchemy.exc import SQLAlchemyError

        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return False
        return True

    def close(self) -> None:
        self.engine.dispose()
