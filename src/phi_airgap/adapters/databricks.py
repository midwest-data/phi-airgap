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
    from ..util import die, keychain_get

    try:
        from databricks import sql as dbsql
    except ImportError:
        die(
            "the Databricks connector is not installed. Reinstall with the extra:\n"
            "  uv tool install --python 3.12 --reinstall 'phi-airgap[databricks]'   "
            "(from the repo: '.[databricks]')"
        )

    return dbsql.connect(
        server_hostname=cfg["host"],
        http_path=cfg["http_path"],
        access_token=keychain_get(),
    )


register("databricks", sys.modules[__name__])
