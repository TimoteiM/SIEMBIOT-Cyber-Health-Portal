from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, text


class LeastPrivilegeError(RuntimeError):
    """The API is connected as a role that row-level security does not apply to."""


class Database:
    def __init__(self, url: str) -> None:
        self.engine: Engine = create_engine(url, pool_pre_ping=True)

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

    def close(self) -> None:
        self.engine.dispose()
