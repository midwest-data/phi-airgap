"""The gate: structural, deterministic classification of a SQL statement.

This is the control. It runs before anything touches the warehouse, and it is
allowed to be wrong only in the safe direction — an unclassified table is RED
and an unparseable statement is denied.

Rules enforced (all deterministic, no heuristics, no model in the loop):

  R0  one statement, read-only, parseable in the configured SQL dialect
  R1  table sources must be named relations — no path reads, no table functions
  R2  every output expression over a non-GREEN table is an aggregate or a
      GROUP BY key
  R3  identifier columns may not be referenced anywhere in the statement, and
      `*` is expanded against the metadata cache before that check runs
  R4  no SELECT DISTINCT over a non-GREEN table (a de-duplicated row dump that
      also carries no count column for k-anonymity to bite on)
  R5  no window functions in the output over a non-GREEN table (they preserve
      row count, so they are not aggregation)
  R6  a non-GREEN aggregate must project a count-like column, so that
      k-anonymity suppression has something to act on
  R7  no LIMIT/OFFSET on a non-aggregated projection — the "peek at 10 rows"
      habit, and paged repetition of it
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

import sqlglot
from sqlglot import exp

from . import util

# One-value swap: the sqlglot dialect the gate parses and re-serialises in.
# Read once at import; restart to change it.
DIALECT = util.config().get("sql_dialect", "databricks")

# Only read statements ever reach the warehouse through the broker.
_ALLOWED_ROOT = (exp.Select, exp.Union, exp.Except, exp.Intersect, exp.Describe, exp.Show)

# Per-developer dev schema mangling: `dev_alice__orders` -> `orders`; bare
# `dev_alice` -> default schema. So a dev copy classifies as its logical table.
_DEV_SCHEMA = re.compile(r"^dev_[a-z0-9]+(?:__(?P<real>.+))?$", re.IGNORECASE)

# R1, belt: a raw-text guard on path-style and function table sources, so a
# sqlglot parse quirk cannot smuggle one past the structural check below.
# `read_files(...)` in particular parses to a Table whose name is the empty
# string, which would otherwise leave the statement with zero known tables.
_PATH_READ = re.compile(
    r"\b(?:read_files|read_kafka|read_statestore|cloud_files|read_pulsar)\s*\("
    r"|\b(?:parquet|delta|json|csv|text|avro|orc|binaryfile|iceberg)\s*\.\s*[`'\"]"
    r"|(?:abfss?|s3a?|gs|wasbs?|dbfs|file)://",
    re.IGNORECASE,
)


@dataclass
class Verdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    tables: dict[str, str] = field(default_factory=dict)  # "cat.sch.tbl" -> RED/AMBER/GREEN
    sql: str = ""
    # Output column names that are GROUP BY keys, not measures. The scrubber
    # needs these to know which cells to blank when a count falls below k.
    group_keys: set[str] = field(default_factory=set)
    # True when every referenced relation is GREEN — relaxes the row ceiling.
    all_green: bool = False

    @property
    def worst(self) -> str:
        for level in ("RED", "AMBER", "GREEN"):
            if level in self.tables.values():
                return level
        return "GREEN"

    def to_dict(self) -> dict:
        return {
            "verdict": "ALLOW" if self.allowed else "DENY",
            "classification": self.worst,
            "tables": self.tables,
            "group_keys": sorted(self.group_keys),
            "reasons": self.reasons,
            "sql": self.sql,
        }


# --- table name normalisation ------------------------------------------------


def _variants(catalog: str, schema: str, table: str) -> set[str]:
    """Every dotted form a policy pattern might reasonably be written against."""
    schemas = {schema}
    if m := _DEV_SCHEMA.match(schema):
        schemas.add(m.group("real") or "")
    catalogs = {catalog}
    if catalog.endswith("_dev"):
        catalogs.add(catalog[: -len("_dev")])

    out = set()
    for c in catalogs:
        for s in schemas:
            out.add(f"{c}.{s}.{table}" if c and s else f"{s}.{table}" if s else table)
            if s:
                out.add(f"{s}.{table}")
            out.add(table)
    return {v.strip(".") for v in out if v}


def classify(catalog: str, schema: str, table: str, pol: dict) -> str:
    forms = _variants(catalog.lower(), schema.lower(), table.lower())
    # red first (fail closed on raw data), then green — the specific, reviewed
    # carve-out list — then amber, the broad catch-all for the mart catalogs.
    # Without green ahead of amber, a broad `analytics.*` amber rule would
    # swallow the `*.metric_targets` green carve-out that lives inside it, and
    # every pre-aggregated read would needlessly have to aggregate again.
    for level in ("red", "green", "amber"):
        for pattern in pol.get(level, []) or []:
            p = pattern.lower()
            if any(fnmatch(f, p) for f in forms):
                return level.upper()
    return "RED"  # fail closed: unknown relation is treated as raw PHI


# --- expression helpers ------------------------------------------------------


def _cte_names(tree: exp.Expression) -> set[str]:
    return {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}


def _tables(tree: exp.Expression) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Named relations, plus any table source that is not a named relation.

    A source with no resolvable name (a table function, a path read) cannot be
    classified, so it can never be permitted — it is returned separately and
    denied outright rather than silently contributing zero tables.
    """
    ctes = _cte_names(tree)
    named: list[tuple[str, str, str]] = []
    unnamed: list[str] = []
    for t in tree.find_all(exp.Table):
        name = (t.name or "").lower()
        if not name or not isinstance(t.this, (exp.Identifier, exp.Dot)):
            unnamed.append(t.sql(dialect=DIALECT)[:120])
            continue
        if name in ctes and not t.db:
            continue
        named.append(((t.catalog or "").lower(), (t.db or "").lower(), name))
    return named, unnamed


def _terminal_selects(tree: exp.Expression) -> list[exp.Select]:
    """The SELECTs whose projections actually leave the boundary.

    Only the outermost projection is rule-checked: if an inner subquery scans
    raw rows but the outer statement aggregates them, nothing row-grain escapes.
    """
    node = tree
    while isinstance(node, exp.Subquery):
        node = node.this
    if isinstance(node, exp.Select):
        return [node]
    if isinstance(node, (exp.Union, exp.Except, exp.Intersect)):
        return _terminal_selects(node.left) + _terminal_selects(node.right)
    return []


def _has_aggregate(e: exp.Expression) -> bool:
    """True only for genuine row-collapsing aggregation.

    Window functions are deliberately excluded: `max(x) over (partition by ...)`
    returns one row per input row, so it is a row dump wearing an aggregate's
    coat. Treating it as aggregation was the single easiest way past this gate.
    """
    return any(isinstance(n, exp.AggFunc) and not _in_window(n) for n in e.walk())


def _in_window(node: exp.Expression) -> bool:
    parent = node.parent
    while parent is not None:
        if isinstance(parent, exp.Window):
            return True
        parent = parent.parent
    return False


def _has_window(e: exp.Expression) -> bool:
    return any(isinstance(n, exp.Window) for n in e.walk())


def _group_keys(select: exp.Select) -> set[str]:
    group = select.args.get("group")
    if not group:
        return set()
    projections = select.expressions
    keys = set()
    for e in group.expressions:
        # `group by 1` is an ordinal into the projection list — resolve it,
        # otherwise every `group by 1, 2` query looks like a bare projection.
        if isinstance(e, exp.Literal) and e.is_int:
            idx = int(e.name) - 1
            if 0 <= idx < len(projections):
                target = projections[idx]
                inner = target.unalias() if isinstance(target, exp.Alias) else target
                keys.add(inner.sql(dialect=DIALECT).lower())
                keys.add((target.alias_or_name or "").lower())
            continue
        keys.add(e.sql(dialect=DIALECT).lower())
        if isinstance(e, exp.Column):
            keys.add(e.name.lower())
    keys.discard("")
    return keys


def _column_tokens(tree: exp.Expression) -> set[str]:
    """Every column-ish name mentioned anywhere in the statement."""
    names = set()
    for c in tree.find_all(exp.Column):
        if c.name:
            names.add(c.name.lower())
    for a in tree.find_all(exp.Alias):
        if a.alias:
            names.add(a.alias.lower())
    return names


def _projects_star(tree: exp.Expression) -> bool:
    """True only for `select *` / `select t.*` in an OUTPUT position.

    Must not walk the whole tree: `count(*)` contains an exp.Star, so a naive
    walk reports a star projection for every aggregate query written.
    """
    for select in _terminal_selects(tree):
        for e in select.expressions:
            if isinstance(e, exp.Star) or (
                isinstance(e, exp.Column) and isinstance(e.this, exp.Star)
            ):
                return True
    return False


def _cached_columns(tables: list[str], index: dict | None) -> dict[str, tuple[str, str]]:
    """{column_name: (relation, description)} for every referenced relation."""
    out: dict[str, tuple[str, str]] = {}
    if not index:
        return out
    for key in tables:
        entry = index.get(key)
        if not entry:
            # Fall back to a suffix match: the cache is keyed on the real dev
            # schema, the query may name the logical one (or vice versa).
            tail = ".".join(key.split(".")[-1:])
            entry = next(
                (v for k, v in index.items() if k.rsplit(".", 1)[-1] == tail),
                None,
            )
        for name, meta in (entry or {}).get("columns", {}).items():
            out.setdefault(name.lower(), (key, meta.get("description", "")))
    return out


# --- the gate ----------------------------------------------------------------


def check(sql: str, pol: dict, index: dict | None = None) -> Verdict:
    """Classify and rule-check a statement. `index` is the metadata cache; when
    supplied, `*` is expanded and column descriptions are screened too."""
    v = Verdict(allowed=False, sql=sql.strip())

    # R0 — parseable, single, read-only.
    try:
        statements = [s for s in sqlglot.parse(sql, dialect=DIALECT) if s is not None]
    except Exception as e:
        v.reasons.append(f"Could not parse as {DIALECT} SQL: {e}")
        return v

    if not statements:
        v.reasons.append("No statement found.")
        return v
    if len(statements) > 1:
        v.reasons.append(
            f"{len(statements)} statements found — phi-airgap runs exactly one SELECT per file."
        )
        return v

    tree = statements[0]
    if not isinstance(tree, _ALLOWED_ROOT):
        v.reasons.append(
            f"{type(tree).__name__.upper()} is not permitted — phi-airgap is read-only, SELECT only."
        )
        return v

    # R1 — named relations only. A path read or table function cannot be
    # classified, so it is denied before anything else is considered.
    if m := _PATH_READ.search(sql):
        v.reasons.append(
            f"Path/table-function source `{m.group(0)}` is denied: it bypasses table "
            "classification entirely. Read through a catalogued relation."
        )
    named, unnamed = _tables(tree)
    for src in unnamed:
        v.reasons.append(
            f"Table source `{src}` has no resolvable relation name, so it cannot be "
            "classified. Denied."
        )

    for cat, sch, tbl in named:
        v.tables[".".join(p for p in (cat, sch, tbl) if p)] = classify(cat, sch, tbl, pol)

    sensitive = {k: lvl for k, lvl in v.tables.items() if lvl != "GREEN"}
    v.all_green = bool(v.tables) and not sensitive

    # Group keys, for the scrubber. By construction of R2 below, any output
    # expression that is not an aggregate must be a GROUP BY key.
    for select in _terminal_selects(tree):
        for e in select.expressions:
            inner = e.unalias() if isinstance(e, exp.Alias) else e
            if not _has_aggregate(inner):
                v.group_keys.add((e.alias_or_name or "").lower())
    v.group_keys.discard("")

    # R3 — identifier columns, anywhere in the statement. `*` is expanded from
    # the metadata cache first, so `select * from a_green_table` is screened on
    # its real columns rather than waved through.
    denied_cols = pol.get("deny_columns", []) or []
    allowed_cols = [p.lower() for p in pol.get("allow_columns", []) or []]
    denied_desc = [p.lower() for p in pol.get("deny_descriptions", []) or []]

    referenced = _column_tokens(tree)
    cached = _cached_columns(list(v.tables), index)
    if _projects_star(tree) and cached:
        referenced |= set(cached)
    elif _projects_star(tree) and v.tables and not cached:
        v.reasons.append(
            "`*` cannot be screened: no cached columns for "
            f"{', '.join(v.tables)}. Ask the user to run `phi-airgap refresh`, or name columns "
            "explicitly."
        )

    for name in sorted(referenced):
        if any(fnmatch(name, p) for p in allowed_cols):
            continue
        hit = next((p for p in denied_cols if fnmatch(name, p.lower())), None)
        if hit:
            v.reasons.append(
                f"Column `{name}` matches denied pattern `{hit}` — direct and quasi "
                "identifiers may not be referenced anywhere in the query (SELECT, WHERE, "
                "JOIN, HAVING or ORDER BY)."
            )
            continue
        # Screen the warehouse/model description too: it catches identifier
        # columns whose *name* is opaque (pat_nm, ptnt_1) but whose documented
        # meaning is not.
        desc = cached.get(name, ("", ""))[1].lower()
        if desc and (bad := next((p for p in denied_desc if fnmatch(desc, p)), None)):
            v.reasons.append(
                f"Column `{name}` is described as {desc[:80]!r}, which matches denied "
                f"description pattern `{bad}`."
            )

    if sensitive:
        listing = ", ".join(f"{t} [{lvl}]" for t, lvl in sensitive.items())
        selects = _terminal_selects(tree)
        if not selects:
            v.reasons.append("Could not resolve the output projection — denying.")

        for select in selects:
            keys = _group_keys(select)

            # R4 — SELECT DISTINCT is a de-duplicated row dump, and it carries
            # no count for k-anonymity to suppress.
            if select.args.get("distinct"):
                v.reasons.append(
                    f"SELECT DISTINCT over {listing} is denied: it returns one row per "
                    "distinct value with no count to suppress. Use `count(*)` with a "
                    "GROUP BY instead."
                )

            for e in select.expressions:
                if isinstance(e, exp.Star) or (
                    isinstance(e, exp.Column) and isinstance(e.this, exp.Star)
                ):
                    v.reasons.append(
                        f"`{e.sql(dialect=DIALECT)}` is a bare projection over {listing} — "
                        "every output expression must be an aggregate or a GROUP BY key."
                    )
                    continue
                inner = e.unalias() if isinstance(e, exp.Alias) else e

                # R5 — window functions preserve row count.
                if _has_window(inner):
                    v.reasons.append(
                        f"Output expression `{e.sql(dialect=DIALECT)}` uses a window "
                        f"function over {listing}. Windows return one row per input row, "
                        "so they are not aggregation."
                    )
                    continue
                if _has_aggregate(inner):
                    continue
                text = inner.sql(dialect=DIALECT).lower()
                if text in keys or (isinstance(inner, exp.Column) and inner.name.lower() in keys):
                    continue
                if isinstance(inner, exp.Literal):
                    continue
                v.reasons.append(
                    f"Output expression `{e.sql(dialect=DIALECT)}` is neither an aggregate "
                    f"nor a GROUP BY key, and the query reads {listing}."
                )

            aggregated = any(_has_aggregate(e) for e in select.expressions)

            # R6a — a GROUP BY with no aggregate in the projection is a
            # DISTINCT in disguise, and its group keys ARE the rows:
            # `select first_name from patient_dim group by 1` passes the
            # "every output is a group key" test while emitting every name.
            if not aggregated:
                v.reasons.append(
                    f"Projection contains no aggregate, so this reads {listing} at row "
                    "grain — a GROUP BY whose keys are the rows is still a row dump. "
                    "Every non-GREEN query must aggregate."
                )

            # R6 — k-anonymity needs a count to act on. Without one, an
            # `avg(los_days)` over a group of three is three patients' data.
            if aggregated and not _projects_count(select, pol):
                v.reasons.append(
                    f"No count-like output column, so k-anonymity suppression cannot "
                    f"apply to this aggregate over {listing}. Add `count(*) as n` (or "
                    "another column matching policy.yml count_columns) so small cells "
                    "can be suppressed."
                )

            # R7 — the "let me just peek at 10 rows" habit, and paging it.
            if (select.args.get("limit") or select.args.get("offset")) and not aggregated:
                v.reasons.append(
                    "LIMIT/OFFSET on a non-aggregated projection is denied outright. To "
                    "inspect a join, use `count(*) ... GROUP BY <join keys>` instead of "
                    "peeking at rows."
                )

    v.allowed = not v.reasons
    return v


def _projects_count(select: exp.Select, pol: dict) -> bool:
    patterns = [p.lower() for p in pol.get("count_columns", []) or []]
    for e in select.expressions:
        name = (e.alias_or_name or "").lower()
        if name and any(fnmatch(name, p) for p in patterns):
            return True
        inner = e.unalias() if isinstance(e, exp.Alias) else e
        if any(isinstance(n, exp.Count) for n in inner.walk()):
            return True
    return False
