from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, text


class LeastPrivilegeError(RuntimeError):
    """The API is connected as a role that row-level security does not apply to."""


class Database:
    def __init__(self, url: str, connect_timeout_seconds: int = 10) -> None:
        # A bounded connect timeout so a misconfigured deployment fails in seconds
        # rather than minutes. Startup verifies the connected role, and without this a
        # wrong host makes the API hang -- which reads as a broken service rather than
        # as the configuration mistake it is.
        self.engine: Engine = create_engine(
            url,
            pool_pre_ping=True,
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
