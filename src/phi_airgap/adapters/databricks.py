"""Reference adapter: Databricks SQL warehouse over the official connector.

The token is read from the macOS Keychain by `util.keychain_get()`, never from
config or the environment where the agent could reach it. Install with
`pip install phi-airgap[databricks]`.
"""

from __future__ import annotations

import sys

from . import register


def connect(cfg: dict):
    """Return a DBAPI connection to the configured Databricks SQL warehouse."""
    from databricks import sql as dbsql

    from ..util import keychain_get

    return dbsql.connect(
        server_hostname=cfg["host"],
        http_path=cfg["http_path"],
        access_token=keychain_get(),
    )


register("databricks", sys.modules[__name__])
