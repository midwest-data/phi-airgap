"""Execute: gate → warehouse → scrub → write. Only the human invokes this."""

from __future__ import annotations

import contextlib
import csv
import json
import sys
from pathlib import Path

from . import gate, scrub, util
from .adapters import get_adapter


@contextlib.contextmanager
def connect():
    cfg = util.config()
    conn = get_adapter(cfg.get("adapter", "databricks")).connect(cfg)
    try:
        yield conn
    finally:
        conn.close()


def fetch(conn, sql: str, max_rows: int = 5000) -> tuple[list[str], list[list]]:
    with conn.cursor() as cur:
        cur.execute(sql)
        columns = [d[0] for d in cur.description]
        rows = [list(r) for r in cur.fetchmany(max_rows)]
    return columns, rows


def _write_outputs(stem: str, verdict_doc: dict, columns=None, rows=None) -> tuple[Path, Path]:
    out = util.phi_airgap_dir() / "out"
    json_path = out / f"{stem}.json"
    csv_path = out / f"{stem}.csv"
    json_path.write_text(json.dumps(verdict_doc, indent=2, default=str))
    if columns is None:
        csv_path.unlink(missing_ok=True)
    else:
        with csv_path.open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(columns)
            w.writerows(rows)
    return csv_path, json_path


def run_file(path: Path) -> int:
    sql = path.read_text()
    stem = path.stem
    pol = util.policy()
    cfg = util.config()

    index = None
    try:  # the cache lets the gate expand `*` and screen column descriptions
        from . import meta

        if meta.cache_path().exists():
            index = meta.load()
    except Exception:
        pass

    verdict = gate.check(sql, pol, index)
    doc = verdict.to_dict()
    doc["source"] = str(path)
    doc["metadata_cache"] = "loaded" if index else "MISSING (run phi-airgap refresh)"

    if not verdict.allowed:
        _write_outputs(stem, doc)
        util.audit(
            event="query", source=str(path), verdict="DENY",
            classification=verdict.worst, reasons=verdict.reasons,
        )
        print(f"DENY  [{verdict.worst}]  {path}", file=sys.stderr)
        for r in verdict.reasons:
            print(f"  - {r}", file=sys.stderr)
        print(f"\nVerdict written to {util.phi_airgap_dir() / 'out' / (stem + '.json')}", file=sys.stderr)
        return 1

    print(f"ALLOW [{verdict.worst}]  {', '.join(verdict.tables) or 'no tables'}")

    # Fetch one row past the ceiling so an over-limit result can be refused
    # rather than silently truncated — truncating a 50,000-row name dump to 200
    # still emits 200 names.
    ceiling = cfg["max_rows"] if verdict.all_green else cfg["max_rows_sensitive"]
    try:
        with connect() as conn:
            columns, rows = fetch(conn, sql, ceiling + 1)
    except Exception as e:
        doc["error"] = f"{type(e).__name__}: {e}"
        _write_outputs(stem, doc)
        util.audit(event="query", source=str(path), verdict="ERROR", error=doc["error"])
        print(f"phi-airgap: query failed: {doc['error']}", file=sys.stderr)
        return 3

    if len(rows) > ceiling:
        doc["error"] = (
            f"Result exceeds the {'GREEN' if verdict.all_green else verdict.worst} row ceiling "
            f"of {ceiling}. A {len(rows)}+ row aggregate over {verdict.worst} data is a row "
            "dump wearing a GROUP BY — nothing was written. Aggregate to a coarser grain, or "
            "raise max_rows_sensitive in config.yml on purpose."
        )
        _write_outputs(stem, doc)
        util.audit(event="query", source=str(path), verdict="ROW_CEILING", rows=len(rows))
        print(f"phi-airgap: {doc['error']}", file=sys.stderr)
        return 5

    try:
        report = scrub.scrub(
            columns,
            rows,
            deny_columns=pol.get("deny_columns", []),
            count_columns=pol.get("count_columns", []),
            allow_columns=pol.get("allow_columns", []),
            group_keys=verdict.group_keys,
            k=cfg["k_threshold"],
            require_presidio=cfg.get("require_presidio", True),
            max_suppressed_share=cfg.get("max_suppressed_share", 0.5),
        )
    except scrub.ScrubFail as e:
        doc["scrub_failed"] = str(e)
        _write_outputs(stem, doc)  # verdict only — the result set is discarded
        util.audit(event="query", source=str(path), verdict="SCRUB_FAIL", error=str(e))
        print(f"phi-airgap: SCRUB FAILED — no output written.\n  {e}", file=sys.stderr)
        return 4

    doc["scrub"] = report.to_dict()
    doc["row_count"] = len(rows)
    csv_path, json_path = _write_outputs(stem, doc, columns, rows)

    util.audit(
        event="query", source=str(path), verdict="ALLOW", classification=verdict.worst,
        tables=verdict.tables, rows=len(rows),
        cells_suppressed=report.cells_suppressed, alarm=report.alarm,
    )

    if report.alarm:
        print(
            "\n*** PHI ALARM *** identifiers matched in the result set and were redacted. "
            "The gate leaked — policy.yml needs fixing before this query shape is used "
            "again. Do not treat the redaction as a save.\n"
            f"    regex: {report.regex_hits[:5]}\n"
            f"    ner:   {report.ner_hits[:5]}\n",
            file=sys.stderr,
        )
    if report.cells_suppressed:
        print(f"k-anonymity: {report.cells_suppressed} cells suppressed to <11")

    _echo(columns, rows)
    print(f"\n-> {csv_path}\n-> {json_path}")
    return 0


def _echo(columns: list[str], rows: list[list], limit: int = 60) -> None:
    widths = [
        max(len(str(c)), *(len(str(r[i])) for r in rows[:limit] or [[""] * len(columns)]))
        for i, c in enumerate(columns)
    ]
    widths = [min(w, 40) for w in widths]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print()
    print(fmt.format(*(str(c)[:40] for c in columns)))
    print(fmt.format(*("-" * w for w in widths)))
    for r in rows[:limit]:
        print(fmt.format(*(str(x)[:40] for x in r)))
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more rows (full result in the csv)")
