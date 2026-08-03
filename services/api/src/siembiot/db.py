from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, text


class Database:
    def __init__(self, url: str) -> None:
        self.engine: Engine = create_engine(url, pool_pre_ping=True)

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
