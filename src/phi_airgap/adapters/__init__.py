"""Warehouse adapter seam.

`run.py` and `meta.py` never import a warehouse driver directly — they call the
adapter named by `config.adapter` (default "databricks"). An adapter is anything
that returns a DBAPI-shaped connection from `connect(cfg)`:

    conn = adapter.connect(cfg)          # cfg is util.config()
    with conn.cursor() as cur:
        cur.execute(sql)
        columns = [d[0] for d in cur.description]   # PEP 249 description
        rows = cur.fetchmany(n)
    conn.close()

That is the whole contract: a `connect(cfg)` callable, a connection with
`cursor()` and `close()`, and a cursor with `execute()`, `description` and
`fetchmany()`. Any PEP 249 driver already satisfies it, so a Postgres or
Snowflake adapter is roughly:

    # phi-airgap/adapters/postgres.py
    def connect(cfg):
        import psycopg
        return psycopg.connect(cfg["host"])   # returns a DBAPI connection
    register("postgres", __import__(__name__))

then set `adapter: postgres` and `sql_dialect: postgres` in config.

# ponytail: only the databricks adapter ships; the seam is the extension point,
# add others on demand.
"""

from __future__ import annotations

import importlib
from typing import Any, Protocol


class Adapter(Protocol):
    def connect(self, cfg: dict) -> Any:  # -> a DBAPI connection
        ...


_REGISTRY: dict[str, Adapter] = {}


def register(name: str, adapter: Adapter) -> None:
    _REGISTRY[name] = adapter


def get_adapter(name: str = "databricks") -> Adapter:
    """Resolve an adapter by name, importing the built-in module on demand."""
    if name not in _REGISTRY:
        try:
            importlib.import_module(f"{__name__}.{name}")
        except ImportError as e:
            raise ImportError(
                f"No warehouse adapter '{name}'. Built-in: 'databricks' "
                f"(install with `pip install phi-airgap[databricks]`). "
                f"For another warehouse, add phi-airgap/adapters/{name}.py — see this "
                f"module's docstring for the ~30-line DBAPI contract. ({e})"
            ) from e
    if name not in _REGISTRY:
        raise ImportError(f"Adapter module '{name}' did not register itself via register().")
    return _REGISTRY[name]
