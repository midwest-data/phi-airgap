"""Metadata cache — the piece that removes most of the demand for live access.

Writing models and reviewing PRs needs schema, not rows. `phi-airgap schema` reads
this cache and never touches the network, so it stays on the agent's allowlist.
"""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path

from . import util

CACHE = "meta/columns.json"


def network_catalogs() -> list[str]:
    """Catalogs worth pulling column metadata from via information_schema.

    Column names are not PHI, so reviewing a source connector needs them — but
    which catalogs exist is deployment-specific, so it is config, not code.
    """
    return list(util.config().get("network_catalogs", []) or [])


def cache_path() -> Path:
    return util.phi_airgap_dir() / CACHE


# --- build -------------------------------------------------------------------


def _from_manifest(path: Path) -> dict:
    """Descriptions, lineage and documented columns from a dbt manifest."""
    m = json.loads(path.read_text())
    out: dict[str, dict] = {}

    def add(node: dict, ident: str) -> None:
        key = ".".join(
            p for p in (node.get("database", ""), node.get("schema", ""), ident) if p
        ).lower()
        entry = out.setdefault(key, {"columns": {}})
        entry["kind"] = node.get("resource_type", "")
        if desc := (node.get("description") or "").strip():
            entry["description"] = desc
        if refs := node.get("depends_on", {}).get("nodes"):
            entry["depends_on"] = sorted(refs)[:40]
        if p := node.get("original_file_path"):
            entry["defined_in"] = p
        for cname, col in (node.get("columns") or {}).items():
            entry["columns"][cname.lower()] = {
                "type": col.get("data_type") or "",
                "description": (col.get("description") or "").strip(),
            }

    for node in m.get("nodes", {}).values():
        if node.get("resource_type") in ("model", "seed", "snapshot"):
            add(node, node.get("alias") or node.get("name", ""))
    for node in m.get("sources", {}).values():
        add(node, node.get("identifier") or node.get("name", ""))
    return out


def _from_information_schema(catalogs: list[str]) -> dict:
    """Authoritative column list. Metadata only — no user data is read."""
    from . import run  # local import: keeps `phi-airgap schema` off the connector path

    out: dict[str, dict] = {}
    sql_tmpl = (
        "select lower(table_catalog), lower(table_schema), lower(table_name), "
        "lower(column_name), data_type, comment "
        "from {cat}.information_schema.columns "
        "where table_schema <> 'information_schema'"
    )
    with run.connect() as conn:
        for cat in catalogs:
            try:
                cols, rows = run.fetch(conn, sql_tmpl.format(cat=cat))
            except Exception as e:  # a catalog we cannot see is not fatal
                print(f"phi-airgap: skipping catalog {cat}: {type(e).__name__}: {e}")
                continue
            for c, s, t, col, dtype, comment in rows:
                entry = out.setdefault(f"{c}.{s}.{t}", {"columns": {}})
                entry["columns"][col] = {
                    "type": dtype or "",
                    "description": (comment or "").strip(),
                }
            print(f"phi-airgap: {cat}: {sum(1 for k in out if k.startswith(cat + '.'))} relations")
    return out


def build(manifests: list[Path], offline: bool) -> dict:
    """Merge manifests and information_schema into one index.

    Optional per-relation `row_count` and per-column `distinct_count` keys drive
    gate rule R14 (person-key enumeration). Neither the dbt manifest nor
    information_schema carries them portably, so they are absent unless a
    deployment adds them (a `phi-airgap refresh` post-step, or by hand); R14 is
    documented as inactive without them.
    """
    index: dict[str, dict] = {}
    for path in manifests:
        if path.exists():
            merged = _from_manifest(path)
            print(f"phi-airgap: {path}: {len(merged)} relations")
            for k, v in merged.items():
                tgt = index.setdefault(k, {"columns": {}})
                tgt["columns"].update(v.pop("columns", {}))
                tgt.update(v)
    if not offline:
        for k, v in _from_information_schema(network_catalogs()).items():
            tgt = index.setdefault(k, {"columns": {}})
            # information_schema is authoritative on type; keep dbt's prose.
            for col, meta in v["columns"].items():
                cur = tgt["columns"].setdefault(col, {})
                cur["type"] = meta["type"]
                cur["description"] = cur.get("description") or meta["description"]
    return index


def save(index: dict) -> Path:
    p = cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(index, indent=1, sort_keys=True))
    return p


def load() -> dict:
    p = cache_path()
    if not p.exists():
        util.die(f"No metadata cache at {p}. Ask the user to run `phi-airgap refresh`.")
    return json.loads(p.read_text())


# --- query -------------------------------------------------------------------


def find(pattern: str, index: dict | None = None) -> dict:
    """Match a relation pattern loosely: bare table name, schema.table, or glob."""
    index = index if index is not None else load()
    pat = pattern.lower()
    if "*" not in pat and "?" not in pat:
        pat = f"*{pat}*"
    hits = {}
    for key, entry in index.items():
        table = key.rsplit(".", 1)[-1]
        schema_table = ".".join(key.split(".")[-2:])
        if fnmatch(key, pat) or fnmatch(schema_table, pat) or fnmatch(table, pat):
            hits[key] = entry
    return hits


def render(hits: dict, columns_only: bool = False) -> str:
    lines = []
    for key in sorted(hits):
        entry = hits[key]
        cols = entry.get("columns", {})
        header = f"{key}  [{entry.get('kind', 'relation')}, {len(cols)} cols]"
        lines.append(header)
        if not columns_only:
            if desc := entry.get("description"):
                lines.append(f"    -- {desc.splitlines()[0][:160]}")
            if src := entry.get("defined_in"):
                lines.append(f"    defined_in: {src}")
        for name in sorted(cols):
            meta = cols[name]
            bit = f"    {name:<44} {meta.get('type', ''):<16}"
            if not columns_only and meta.get("description"):
                bit += f" -- {meta['description'].splitlines()[0][:100]}"
            lines.append(bit.rstrip())
        lines.append("")
    return "\n".join(lines) if lines else "no matching relation in the cache"


# --- policy draft ------------------------------------------------------------


def draft_policy(index: dict, pol: dict) -> str:
    """List every cached relation that falls through to RED, for human review."""
    from .gate import classify

    buckets: dict[str, list[str]] = {"RED": [], "AMBER": [], "GREEN": []}
    for key in sorted(index):
        parts = key.split(".")
        cat, sch, tbl = (["", ""] + parts)[-3:]
        buckets[classify(cat, sch, tbl, pol)].append(key)

    out = [
        "# phi-airgap policy review sheet — generated by `phi-airgap refresh --draft-policy`.",
        "# Read this, then edit policy.yml. This file is NOT loaded at runtime.",
        f"# {len(index)} relations in the cache.",
        "",
    ]
    for level in ("GREEN", "AMBER", "RED"):
        out.append(f"# ---- {level}: {len(buckets[level])} relations ----")
        for key in buckets[level]:
            out.append(f"#   {key}")
        out.append("")
    out.append(
        "# Anything above in RED that is genuinely a pre-aggregated, identifier-free\n"
        "# mart should be promoted to `green:` in policy.yml. Everything else stays."
    )
    return "\n".join(out)
