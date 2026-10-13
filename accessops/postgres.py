"""PostgreSQL access: group roles per catalog role, login roles per person.

Every catalog role maps to a NOLOGIN group role `ao_<role>` that holds the privileges.
Granting access = create a LOGIN role for the person and make it a member of the group.
All names go through psycopg.sql.Identifier; values go through parameters or sql.Literal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg import sql

from accessops.catalog import Catalog, Role
from accessops.config import Settings
from accessops.credentials import delete_credentials, new_password, save_credentials
from accessops.db import connect
from accessops.errors import ConflictError
from accessops.outcome import Inventory, Outcome

GROUP_PREFIX = "ao_"
MANAGED_MARKER = "managed-by:accessops"
APPDB_SQL = Path(__file__).parent / "sql" / "appdb.sql"

_USER_STATE_SQL = """
    SELECT shobj_description(r.oid, 'pg_authid') = %(marker)s,
           array(SELECT substr(g.rolname, length(%(prefix)s) + 1)
                 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                 WHERE m.member = r.oid AND starts_with(g.rolname, %(prefix)s)
                 ORDER BY 1)
    FROM pg_roles r
    WHERE r.rolname = %(name)s
"""


def group_role(role_name: str) -> str:
    return f"{GROUP_PREFIX}{role_name}"


@dataclass
class _UserState:
    managed: bool
    roles: list[str]


class PostgresBackend:
    system = "postgres"

    def __init__(self, settings: Settings, catalog: Catalog) -> None:
        self._settings = settings
        self._catalog = catalog
        self._target = catalog.targets.postgres

    # ---- setup -----------------------------------------------------------

    def setup(self) -> list[str]:
        """Create appdb with test data and converge group roles to the catalog."""
        steps = []
        database = self._target.database
        with connect(self._settings, self._settings.pg_admin_db, autocommit=True) as conn:
            exists = conn.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (database,)
            ).fetchone()
            if not exists:
                conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                steps.append(f"created database {database}")
            # By default PUBLIC may connect to every database. Only group roles may.
            for (name,) in conn.execute(
                "SELECT datname FROM pg_database WHERE NOT datistemplate"
            ).fetchall():
                conn.execute(
                    sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
                )
            steps.append("revoked default PUBLIC access to all databases")

        schema = sql.Identifier(self._target.schema_name)
        with connect(self._settings, database) as conn:
            seed = sql.SQL(APPDB_SQL.read_text(encoding="utf-8")).format(schema=schema)
            conn.execute(seed)
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            steps.append(f"schema {self._target.schema_name} with test data is ready")
            for role_name, role in self._catalog.roles.items():
                self._apply_group(conn, role_name, role)
                steps.append(f"group role {group_role(role_name)} matches the catalog")
        return steps

    def _apply_group(self, conn: psycopg.Connection, role_name: str, role: Role) -> None:
        group = group_role(role_name)
        ids = {
            "g": sql.Identifier(group),
            "db": sql.Identifier(self._target.database),
            "schema": sql.Identifier(self._target.schema_name),
            # Privilege keywords come from a fixed whitelist (TablePrivilege), not from users.
            "privs": sql.SQL(", ").join(sql.SQL(p) for p in role.postgres.table_privileges),
        }
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (group,)).fetchone():
            conn.execute(sql.SQL("CREATE ROLE {g} NOLOGIN").format(**ids))
        statements = [
            "GRANT CONNECT ON DATABASE {db} TO {g}",
            "REVOKE ALL ON SCHEMA {schema} FROM {g}",
            "GRANT USAGE ON SCHEMA {schema} TO {g}",
            "REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {g}",
            "GRANT {privs} ON ALL TABLES IN SCHEMA {schema} TO {g}",
            "REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schema} FROM {g}",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} REVOKE ALL ON TABLES FROM {g}",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT {privs} ON TABLES TO {g}",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} REVOKE ALL ON SEQUENCES FROM {g}",
        ]
        if role.postgres.schema_create:
            statements.append("GRANT CREATE ON SCHEMA {schema} TO {g}")
        if "INSERT" in role.postgres.table_privileges:
            statements += [
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {g}",
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
                "GRANT USAGE, SELECT ON SEQUENCES TO {g}",
            ]
        for statement in statements:
            conn.execute(sql.SQL(statement).format(**ids))

    # ---- state -----------------------------------------------------------

    def _user_state(self, conn: psycopg.Connection, subject: str) -> _UserState | None:
        row = conn.execute(
            _USER_STATE_SQL, {"marker": MANAGED_MARKER, "prefix": GROUP_PREFIX, "name": subject}
        ).fetchone()
        if row is None:
            return None
        return _UserState(managed=bool(row[0]), roles=list(row[1]))

    @staticmethod
    def _ensure_managed(subject: str, state: _UserState) -> None:
        if not state.managed:
            raise ConflictError(
                f"Postgres role '{subject}' exists but is not managed by AccessOps; "
                "refusing to touch it."
            )

    def inventory(self) -> Inventory:
        with connect(self._settings, self._settings.pg_admin_db) as conn:
            rows = conn.execute(
                """
                SELECT r.rolname,
                       shobj_description(r.oid, 'pg_authid') IS NOT DISTINCT FROM %(marker)s,
                       array(SELECT substr(g.rolname, length(%(prefix)s) + 1)
                             FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                             WHERE m.member = r.oid AND starts_with(g.rolname, %(prefix)s)
                             ORDER BY 1)
                FROM pg_roles r
                WHERE r.rolcanlogin
                   OR shobj_description(r.oid, 'pg_authid') IS NOT DISTINCT FROM %(marker)s
                ORDER BY 1
                """,
                {"prefix": GROUP_PREFIX, "marker": MANAGED_MARKER},
            ).fetchall()
        managed: list[tuple[str, str | None]] = []
        foreign = []
        for name, is_managed, roles in rows:
            if is_managed:
                managed += [(name, role) for role in roles] or [(name, None)]
            else:
                foreign.append(name)
        return Inventory(managed=managed, foreign=foreign)

    def list_assignments(self) -> list[tuple[str, str | None]]:
        return self.inventory().managed

    # ---- grant / revoke --------------------------------------------------

    def grant(self, subject: str, role_name: str, *, dry_run: bool) -> Outcome:
        group = group_role(role_name)
        user = sql.Identifier(subject)
        with connect(self._settings, self._target.database) as conn:
            if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (group,)).fetchone():
                raise ConflictError(
                    f"Group role {group} does not exist. Run `python -m accessops init` first."
                )
            state = self._user_state(conn, subject)
            steps = []
            if state is None:
                steps += [
                    f"create login role {subject} with a random password",
                    f"mark {subject} as managed by AccessOps",
                ]
            else:
                self._ensure_managed(subject, state)
                other = [r for r in state.roles if r != role_name]
                if other:
                    raise ConflictError(
                        f"'{subject}' already has role '{other[0]}' in postgres; revoke it first."
                    )
                if role_name in state.roles:
                    return Outcome(
                        self.system, False, role_name, [f"{subject} already has {role_name}"]
                    )
            steps.append(f"grant {group} to {subject}")
            if dry_run:
                return Outcome(self.system, True, role_name, steps)

            written: Path | None = None
            try:
                if state is None:
                    password = new_password()
                    conn.execute(
                        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                            user, sql.Literal(password)
                        )
                    )
                    conn.execute(
                        sql.SQL("COMMENT ON ROLE {} IS {}").format(
                            user, sql.Literal(MANAGED_MARKER)
                        )
                    )
                    written = save_credentials(
                        self._settings.credentials_dir,
                        subject,
                        self.system,
                        {
                            "host": self._settings.pg_host,
                            "port": str(self._settings.pg_port),
                            "dbname": self._target.database,
                            "user": subject,
                            "password": password,
                        },
                    )
                conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), user))
                conn.commit()
            except Exception:
                conn.rollback()
                if written:
                    written.unlink(missing_ok=True)
                raise
        return Outcome(self.system, True, role_name, steps, written)

    def revoke(self, subject: str, *, dry_run: bool) -> Outcome:
        user = sql.Identifier(subject)
        with connect(self._settings, self._target.database, autocommit=True) as conn:
            state = self._user_state(conn, subject)
            if state is None:
                return Outcome(self.system, False, None, [f"{subject} does not exist"])
            self._ensure_managed(subject, state)
            role = state.roles[0] if state.roles else None
            steps = [
                f"disable login for {subject}",
                f"terminate active sessions of {subject}",
                *[f"revoke {group_role(r)} from {subject}" for r in state.roles],
                f"drop objects and privileges owned by {subject}",
                f"drop role {subject}",
            ]
            if dry_run:
                return Outcome(self.system, True, role, steps)

            conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(user))
            conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s",
                (subject,),
            )
            with conn.transaction():
                for r in state.roles:
                    conn.execute(
                        sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(group_role(r)), user)
                    )
                conn.execute(sql.SQL("REASSIGN OWNED BY {} TO CURRENT_USER").format(user))
                conn.execute(sql.SQL("DROP OWNED BY {}").format(user))
                conn.execute(sql.SQL("DROP ROLE {}").format(user))
        if delete_credentials(self._settings.credentials_dir, subject, self.system):
            steps.append("delete credentials file")
        return Outcome(self.system, True, role, steps)
