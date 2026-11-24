"""Postgres via psycopg 3; credentials belong only to the broker process."""

import os
import re
import sys

from ..util import die
from . import register


def connect(cfg: dict):
    dsn = os.environ.get(cfg.get("dsn_env", "PHI_AIRGAP_PG_DSN"))
    if not dsn:
        die("Postgres DSN environment variable is unset.")
    timeout = str(cfg.get("statement_timeout", "15s"))
    if not re.fullmatch(r"[1-9][0-9]*(?:ms|s|min)?", timeout):
        die("statement_timeout must be a positive integer with optional ms, s or min unit.")
    try:
        import psycopg
    except ImportError:
        die(
            "psycopg is not installed. Install 'phi-airgap[postgres]' "
            "(from the repo: '.[postgres]')."
        )
    try:
        # Startup options apply before the first transaction (metadata reads too).
        conn = psycopg.connect(
            dsn,
            autocommit=True,
            options=f"-c default_transaction_read_only=on -c statement_timeout={timeout}",
        )
    except Exception:
        die("Postgres connection failed.")  # Driver errors can contain credentials.

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    EXISTS (SELECT 1 FROM pg_roles
                            WHERE rolname = current_user
                            AND (rolsuper OR rolcreaterole OR rolcreatedb
                                 OR rolbypassrls OR rolreplication))
                    OR EXISTS (
                        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                        AND relkind IN ('r', 'p', 'v', 'm', 'f')
                        AND (has_table_privilege(
                            current_user, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE')
                             OR has_any_column_privilege(current_user, c.oid, 'INSERT,UPDATE')))
                    OR EXISTS (
                        SELECT 1 FROM pg_namespace
                        WHERE has_schema_privilege(current_user, oid, 'CREATE'))
            """)
            result = cur.fetchone()
            safe = result is not None and result[0] is False
    except Exception:
        conn.close()
        die("Postgres role privilege verification failed.")
    if not safe:
        conn.close()
        die("Postgres role must be non-superuser with no table write or schema CREATE rights.")
    return conn


register("postgres", sys.modules[__name__])
