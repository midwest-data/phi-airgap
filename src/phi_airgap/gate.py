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
      `*` is expanded against the metadata cache before that check runs; a
      date-ish denied column is tolerated only inside a month/quarter/year
      truncation (R13)
  R4  no SELECT DISTINCT over a non-GREEN table (a de-duplicated row dump that
      also carries no count column for k-anonymity to bite on)
  R5  no window functions in the output over a non-GREEN table (they preserve
      row count, so they are not aggregation)
  R6  a non-GREEN aggregate must project a count-like column, so that
      k-anonymity suppression has something to act on
  R7  no LIMIT/OFFSET on a non-aggregated projection — the "peek at 10 rows"
      habit, and paged repetition of it
  R8  no value-preserving "aggregates" over a non-GREEN table (collect_list,
      any_value, first, ...) — they return row values, not a statistic; min/max
      are allowed only over a column the cache types as numeric/date, an
      allowlisted/count column, or an allowed date truncation
  R9  no CASE/IF/FILTER inside an aggregate whose predicate names a non-allow
      column — a targeted count or measure describes one person while the
      projected count(*) describes the whole table
  R10 no HAVING that compares a count against a literal below k, and no
      LIMIT/OFFSET below k on a non-GREEN aggregate — existence probes
  R11 no ROLLUP / CUBE / GROUPING SETS over non-GREEN — the marginals are
      complementary-suppression fodder
  R12 UNION / EXCEPT / INTERSECT over non-GREEN need identical GROUP BY keys in
      every branch — a `union all select 'ALL', count(*)` marginal is the same
  R13 see R3
  R14 when the cache carries row/distinct counts, a non-allow group key whose
      distinct count is ≥ half the row count is a person key — denied
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

import sqlglot
from sqlglot import exp

from . import util


def dialect() -> str:
    """The sqlglot dialect the gate parses and re-serialises in (config)."""
    return util.config().get("sql_dialect", "databricks")


# Set per check() call so tests and the selftest do not depend on import order.
DIALECT = "databricks"

# R8: aggregate functions that return one or more INPUT VALUES rather than a
# statistic. Over a non-GREEN table they are a row dump wearing GROUP BY.
_VALUE_AGGS = (
    exp.ArrayAgg, exp.ArrayUniqueAgg, exp.GroupConcat, exp.AnyValue, exp.First, exp.Last,
    exp.FirstValue, exp.LastValue, exp.ApproxTopK, exp.Mode,
)
_VALUE_AGG_NAMES = {
    "collect_list", "collect_set", "array_agg", "string_agg", "listagg", "any_value", "first",
    "last", "first_value", "last_value", "mode", "approx_top_k", "group_concat",
}
_NUMERIC_OR_DATE_TYPE = re.compile(
    r"^(?:int|bigint|smallint|tinyint|long|double|float|real|decimal|numeric|date|timestamp)",
    re.IGNORECASE,
)

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

# R13: a date-ish column name (Safe Harbor: dates finer than a year are
# identifiers) may appear only inside one of these truncations.
_DATEISH = re.compile(r"(?:_date$|_dt$|_ts$|_time$|timestamp|^dod$|death|admit|discharge)")
_TRUNC_NODES = (exp.Year, exp.Month, exp.Quarter, exp.TimestampTrunc, exp.DateTrunc)
_TRUNC_UNITS = {"MONTH", "MON", "MM", "QUARTER", "Q", "YEAR", "YY", "YYYY"}
# Transparent wrappers sqlglot inserts between a column and its truncation.
_TRANSPARENT = (exp.TsOrDsToDate, exp.Cast, exp.Paren, exp.TimeStrToTime, exp.TsOrDsToTimestamp)


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
    # Output names whose unaliased expression is a count (count, count_if,
    # count(*) filter (...), sum(case ... 1 else 0)). The scrubber suppresses
    # on these regardless of what they were called.
    count_cols: set[str] = field(default_factory=set)

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
            "count_cols": sorted(self.count_cols),
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
    catalog, schema, table = catalog.lower(), schema.lower(), table.lower()
    forms = _variants(catalog, schema, table)
    # red first (fail closed on raw data), then green — the specific, reviewed
    # carve-out list — then amber, the broad catch-all for the mart catalogs.
    # Without green ahead of amber, a broad `analytics.*` amber rule would
    # swallow the `*.metric_targets` green carve-out that lives inside it, and
    # every pre-aggregated read would needlessly have to aggregate again.
    for level in ("red", "green", "amber"):
        for pattern in pol.get(level, []) or []:
            p = pattern.lower()
            if any(fnmatch(f, p) for f in forms):
                # GREEN cannot be minted: anything the agent can write to (a
                # dev schema, a *_dev catalog) is at most AMBER.
                if level == "green" and (_DEV_SCHEMA.match(schema) or catalog.endswith("_dev")):
                    return "AMBER"
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


def _unwrap(tree: exp.Expression) -> exp.Expression:
    while isinstance(tree, exp.Subquery):
        tree = tree.this
    return tree


def _terminal_selects(tree: exp.Expression) -> list[exp.Select]:
    """The SELECTs whose projections actually leave the boundary.

    Only the outermost projection is rule-checked: if an inner subquery scans
    raw rows but the outer statement aggregates them, nothing row-grain escapes.
    """
    node = _unwrap(tree)
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


def _value_agg(e: exp.Expression) -> str | None:
    """Name of the first value-preserving aggregate in the expression, if any."""
    for n in e.walk():
        if isinstance(n, _VALUE_AGGS):
            return n.sql_name().lower()
        if isinstance(n, exp.Anonymous) and n.name.lower() in _VALUE_AGG_NAMES:
            return n.name.lower()
    return None


def _is_count(e: exp.Expression) -> bool:
    """A count-shaped aggregate: count, count_if, count(...) filter (where ...),
    or sum(case when ... then 1 else 0 end) — anything whose value is a number
    of rows, so that k-anonymity suppression can act on it."""
    if isinstance(e, (exp.Count, exp.CountIf)):
        return True
    if isinstance(e, exp.Filter):
        return isinstance(e.this, (exp.Count, exp.CountIf))
    if isinstance(e, exp.Sum) and isinstance(e.this, exp.Case):
        case = e.this
        branches = [i.args.get("true") for i in case.args.get("ifs", [])]
        branches.append(case.args.get("default"))
        return all(
            b is None or (isinstance(b, exp.Literal) and not b.is_string and b.name in ("0", "1"))
            for b in branches
        )
    return False


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
    """Every column-ish name mentioned anywhere in the statement — including a
    field pulled out of a map/struct/JSON column, so `attrs['ssn']`,
    `p.info.ssn` and `get_json_object(p, '$.mrn')` all hit deny_columns."""
    names = set()
    for c in tree.find_all(exp.Column):
        if c.name:
            names.add(c.name.lower())
    for a in tree.find_all(exp.Alias):
        if a.alias:
            names.add(a.alias.lower())
    for b in tree.find_all(exp.Bracket):
        for lit in b.expressions:
            if isinstance(lit, exp.Literal) and lit.is_string:
                names.add(lit.name.lower())
    for d in tree.find_all(exp.Dot):
        for ident in d.find_all(exp.Identifier):
            names.add(ident.name.lower())
    for k in tree.find_all(exp.JSONPathKey):
        names.add(str(k.this).lower())
    for j in tree.find_all(exp.JSONExtract, exp.JSONExtractScalar):
        path = j.expression
        if isinstance(path, exp.Literal):
            names.add(path.name.split(".")[-1].strip("[]'\"").lower())
    names.discard("")
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


def _cached_columns(tables: list[str], index: dict | None) -> dict[str, tuple[str, str, str]]:
    """{column_name: (relation, description, type)} for every referenced relation."""
    out: dict[str, tuple[str, str, str]] = {}
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
            out.setdefault(name.lower(), (key, meta.get("description", ""), meta.get("type", "")))
    return out


def _cached_entries(tables: list[str], index: dict | None) -> list[dict]:
    if not index:
        return []
    out = []
    for key in tables:
        entry = index.get(key)
        if not entry:
            tail = key.rsplit(".", 1)[-1]
            entry = next((v for k, v in index.items() if k.rsplit(".", 1)[-1] == tail), None)
        if entry:
            out.append(entry)
    return out


def _only_truncated(tree: exp.Expression, name: str) -> bool:
    """R13: every reference to column `name` sits inside a month/quarter/year
    truncation (with at most transparent casts in between)."""
    cols = [c for c in tree.find_all(exp.Column) if c.name.lower() == name]
    if not cols:
        return False
    return all(_truncation_of(c) is not None for c in cols)


def _truncation_of(col: exp.Column) -> exp.Expression | None:
    node = col.parent
    while isinstance(node, _TRANSPARENT):
        node = node.parent
    if isinstance(node, (exp.Year, exp.Month, exp.Quarter)):
        return node
    if isinstance(node, (exp.TimestampTrunc, exp.DateTrunc)):
        unit = node.args.get("unit")
        if unit is not None and unit.name.upper() in _TRUNC_UNITS:
            return node
    return None


def _predicate_columns(agg: exp.Expression) -> set[str]:
    """Columns named in the predicates of any CASE/IF/FILTER inside an aggregate."""
    names: set[str] = set()
    for n in agg.walk():
        preds: list[exp.Expression] = []
        if isinstance(n, exp.Case):
            preds = [i.this for i in n.args.get("ifs", [])]
        elif isinstance(n, exp.If):
            preds = [n.this]
        elif isinstance(n, exp.Filter):
            preds = [n.expression]
        for p in preds:
            names |= {c.name.lower() for c in p.find_all(exp.Column) if c.name}
    return names


def _small_literal(e: exp.Expression | None, k: int) -> bool:
    return isinstance(e, exp.Literal) and e.is_int and int(e.name) < k


def _having_probe(having: exp.Expression, k: int) -> bool:
    """HAVING count(...) <, <=, = or BETWEEN a literal below k."""
    for n in having.walk():
        if isinstance(n, (exp.LT, exp.LTE, exp.EQ)):
            a, b = n.this, n.expression
            if (_is_count(a) and _small_literal(b, k)) or (_is_count(b) and _small_literal(a, k)):
                return True
        if isinstance(n, exp.GT | exp.GTE):
            a, b = n.this, n.expression
            if _small_literal(a, k) and _is_count(b):  # `3 > count(*)`
                return True
        if isinstance(n, exp.Between) and _is_count(n.this):
            if _small_literal(n.args.get("low"), k):
                return True
    return False


# --- the gate ----------------------------------------------------------------


def check(
    sql: str,
    pol: dict,
    index: dict | None = None,
    dialect_name: str | None = None,
    k: int | None = None,
) -> Verdict:
    """Classify and rule-check a statement. `index` is the metadata cache; when
    supplied, `*` is expanded and column descriptions are screened too."""
    global DIALECT
    DIALECT = dialect_name or dialect()
    k = k if k is not None else int(util.config().get("k_threshold", 11))
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
            f"{type(tree).__name__.upper()} is not permitted — phi-airgap is read-only, "
            "SELECT only."
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

    sensitive = {k_: lvl for k_, lvl in v.tables.items() if lvl != "GREEN"}
    v.all_green = bool(v.tables) and not sensitive

    # Group keys, for the scrubber. By construction of R2 below, any output
    # expression that is not an aggregate must be a GROUP BY key.
    for select in _terminal_selects(tree):
        for e in select.expressions:
            inner = e.unalias() if isinstance(e, exp.Alias) else e
            if not _has_aggregate(inner):
                v.group_keys.add((e.alias_or_name or "").lower())
            elif _is_count(inner):
                v.count_cols.add((e.alias_or_name or "").lower())
    v.group_keys.discard("")
    v.count_cols.discard("")

    # R3 — identifier columns, anywhere in the statement. `*` is expanded from
    # the metadata cache first, so `select * from a_green_table` is screened on
    # its real columns rather than waved through.
    denied_cols = pol.get("deny_columns", []) or []
    allowed_cols = [p.lower() for p in pol.get("allow_columns", []) or []]
    count_pats = [p.lower() for p in pol.get("count_columns", []) or []]
    denied_desc = [p.lower() for p in pol.get("deny_descriptions", []) or []]

    def is_allowed(name: str) -> bool:
        return any(fnmatch(name, p) for p in allowed_cols)

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
        if is_allowed(name):
            continue
        hit = next((p for p in denied_cols if fnmatch(name, p.lower())), None)
        if hit:
            # R13 — a date-ish column survives the denylist only inside an
            # allowed truncation: `date_trunc('month', admit_ts)` is a reporting
            # period, `admit_ts` and `date_trunc('hour', admit_ts)` are not.
            if _DATEISH.search(name) and _only_truncated(tree, name):
                continue
            v.reasons.append(
                f"Column `{name}` matches denied pattern `{hit}` — direct and quasi "
                "identifiers may not be referenced anywhere in the query (SELECT, WHERE, "
                "JOIN, HAVING or ORDER BY)."
                + (
                    " Date columns are allowed only as `date_trunc('month'|'quarter'|'year', "
                    "col)`, `year(col)` or `month(col)`."
                    if _DATEISH.search(name)
                    else ""
                )
            )
            continue
        # Screen the warehouse/model description too: it catches identifier
        # columns whose *name* is opaque (pat_nm, ptnt_1) but whose documented
        # meaning is not.
        desc = cached.get(name, ("", "", ""))[1].lower()
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

        # R12 — set operations must agree on their grouping, or one branch is
        # the other's marginal.
        root = _unwrap(tree)
        if isinstance(root, (exp.Union, exp.Except, exp.Intersect)):
            keysets = [frozenset(_group_keys(s)) for s in selects]
            if len(set(keysets)) > 1:
                v.reasons.append(
                    f"{type(root).__name__.upper()} over {listing} with differing GROUP BY "
                    "keys across branches is denied: one branch is a marginal of the other, "
                    "and a suppressed cell can be recovered by subtraction. Give every "
                    "branch the identical GROUP BY."
                )

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

            # R11 — ROLLUP / CUBE / GROUPING SETS emit the marginals.
            if select.find(exp.Rollup, exp.Cube, exp.GroupingSets):
                v.reasons.append(
                    f"ROLLUP/CUBE/GROUPING SETS over {listing} is denied: the subtotal rows "
                    "let a suppressed cell be recovered by subtraction."
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
                text = e.sql(dialect=DIALECT)

                # R5 — window functions preserve row count.
                if _has_window(inner):
                    v.reasons.append(
                        f"Output expression `{text}` uses a window function over {listing}. "
                        "Windows return one row per input row, so they are not aggregation."
                    )
                    continue
                # R8 — value-preserving aggregates return row values.
                if fn := _value_agg(inner):
                    v.reasons.append(
                        f"Output expression `{text}` uses `{fn}` over {listing}, which "
                        "returns individual row values, not a statistic."
                    )
                    continue
                if _has_aggregate(inner):
                    # R8 — min/max return one row's value unless the column is
                    # a number or a date.
                    for mm in inner.find_all(exp.Min, exp.Max):
                        arg = mm.this
                        ok = False
                        if isinstance(arg, exp.Column):
                            n = arg.name.lower()
                            ctype = cached.get(n, ("", "", ""))[2]
                            ok = (
                                is_allowed(n)
                                or any(fnmatch(n, p) for p in count_pats)
                                or bool(_NUMERIC_OR_DATE_TYPE.match(ctype))
                            )
                        elif isinstance(arg, _TRUNC_NODES):
                            ok = True
                        if not ok:
                            why = (
                                "no metadata cache — ask the user to run `phi-airgap refresh`"
                                if not cached
                                else "the cache does not type it as numeric/date"
                            )
                            v.reasons.append(
                                f"`{text}`: min/max over {listing} returns one row's value. "
                                f"Allowed only over a column typed numeric/date ({why}), an "
                                "allow_columns/count column, or a month/quarter/year truncation."
                            )
                            break
                    # R9 — a targeted predicate inside an aggregate.
                    pred_cols = {c for c in _predicate_columns(inner) if not is_allowed(c)}
                    if pred_cols:
                        v.reasons.append(
                            f"`{text}`: CASE/IF/FILTER inside an aggregate names "
                            f"{', '.join(sorted(pred_cols))}, so it describes the rows matching "
                            "that predicate while the projected count describes the whole "
                            "group. Project `count_if(<pred>) as n` and filter in WHERE instead."
                        )
                    continue
                low = inner.sql(dialect=DIALECT).lower()
                if low in keys or (isinstance(inner, exp.Column) and inner.name.lower() in keys):
                    continue
                if isinstance(inner, exp.Literal):
                    continue
                v.reasons.append(
                    f"Output expression `{text}` is neither an aggregate nor a GROUP BY key, "
                    f"and the query reads {listing}."
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
            if aggregated and not _projects_count(select):
                v.reasons.append(
                    f"No bare `count(...)` output column, so k-anonymity suppression cannot "
                    f"apply to this aggregate over {listing}. Add `count(*) as n` so small "
                    "cells can be suppressed (an arithmetic count like `count(*) * 100` "
                    "does not qualify)."
                )

            limit, offset = select.args.get("limit"), select.args.get("offset")
            # R7 — the "let me just peek at 10 rows" habit, and paging it.
            if (limit or offset) and not aggregated:
                v.reasons.append(
                    "LIMIT/OFFSET on a non-aggregated projection is denied outright. To "
                    "inspect a join, use `count(*) ... GROUP BY <join keys>` instead of "
                    "peeking at rows."
                )
            # R10 — existence probes: a tiny LIMIT or a HAVING that selects
            # small cells emits identifying group keys with `<k` beside them.
            if aggregated:
                for node in (limit, offset):
                    if node is not None and _small_literal(node.expression, k):
                        v.reasons.append(
                            f"LIMIT/OFFSET below k={k} on an aggregate over {listing} is an "
                            "existence probe: it returns a handful of group keys with their "
                            "counts suppressed. Drop the LIMIT or raise it to at least k."
                        )
                having = select.args.get("having")
                if having is not None and _having_probe(having, k):
                    v.reasons.append(
                        f"HAVING that selects counts below k={k} over {listing} is an "
                        "existence probe: the surviving group keys identify the small cells."
                    )

            # R14 — a group key that is (nearly) unique per row is a person
            # key, whatever it is called. Needs row/distinct counts in the cache.
            for entry in _cached_entries(list(sensitive), index):
                rc = entry.get("row_count")
                if not rc:
                    continue
                for key in keys:
                    col = entry.get("columns", {}).get(key, {})
                    dc = col.get("distinct_count")
                    if dc and not is_allowed(key) and dc >= 0.5 * rc:
                        v.reasons.append(
                            f"Group key `{key}` has {dc} distinct values over {rc} rows in the "
                            "cache — that is a person key, and grouping by it enumerates "
                            "individuals. Add it to deny_columns."
                        )

    v.allowed = not v.reasons
    return v


def _projects_count(select: exp.Select) -> bool:
    """At least one projection is a bare count (not `count(*) * 100`).

    Name matching against policy count_columns is deliberately NOT done here:
    `count(*) * 100 as n` defeats k-anon while wearing a count-like name.
    """
    return any(
        _is_count(e.unalias() if isinstance(e, exp.Alias) else e) for e in select.expressions
    )
