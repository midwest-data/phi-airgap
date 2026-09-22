"""The scrubber: last line of defence between a result set and the transcript.

Three independent passes:
  1. structural column check  — deterministic, HARD FAIL (nothing is emitted)
  2. k-anonymity suppression  — small cells become "<11"
  3. Presidio NER             — the ALARM. A hit means the gate leaked and the
                                policy needs fixing; it is not a save.

Presidio has false negatives by construction. Never treat a clean NER pass as
proof that a result set is PHI-free.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

REDACT = "<REDACTED:{}>"
SUPPRESSED = "<11"

# Deliberately narrow. DATE_TIME and LOCATION are omitted: they fire on every
# reporting month and every hospital name, and the real Safe Harbor exposures
# they would catch (DOB, patient address) are already denied structurally by
# policy.yml deny_columns plus the gate's aggregation requirement. An alarm
# that cries wolf on `2025-07` and `Mercy General Hospital` gets ignored.
_NER_ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "US_SSN",
    "MEDICAL_LICENSE",
    "US_DRIVER_LICENSE",
    "CREDIT_CARD",
    "IP_ADDRESS",
]

_NUMERIC = re.compile(r"^-?[\d,]+(\.\d+)?$")

# ── Deterministic layer ──────────────────────────────────────────────────────
# Regex, not NER. These shapes never legitimately appear in an aggregate
# result, and unlike the model they cannot miss. Measured: Presidio scored
# `ssn 123-45-6789` at zero — the SSN recognizer needs surrounding context it
# will not always get. Deterministic patterns are the floor that the
# statistical layer sits on top of, never the reverse.
#
# Digit runs are keyword-anchored on purpose: a bare `\d{7,12}` rule would
# redact a legitimate seven-digit aggregate total as an MRN.
_DETERMINISTIC: list[tuple[str, re.Pattern]] = [
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("US_SSN", re.compile(r"\b(?<![-\d])\d{9}(?![-\d])\b(?=[^\n]{0,20}\bssn\b)", re.I)),
    (
        "PHONE_NUMBER",
        re.compile(r"(?<![\d-])(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\d-])"),
    ),
    ("EMAIL_ADDRESS", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    (
        "RECORD_NUMBER",
        re.compile(
            r"(?i)\b(?:mrn|medical\s+record(?:\s+(?:no|number|#))?|csn|contact\s+serial"
            r"|acct|account(?:\s+(?:no|number|#))?|patient\s+(?:id|no|number|#))\b"
            r"[^\w\n]{0,12}\d{5,14}\b"
        ),
    ),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[- ]){3}\d{4}\b")),
    # Credentials that must never land in a transcript. GitHub PATs by prefix,
    # plus any secret introduced by a labelling keyword (catches warehouse PATs,
    # bearer tokens, api keys) without hard-coding one vendor's token shape.
    ("TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    (
        "TOKEN",
        re.compile(
            r"(?i)\b(?:token|secret|api[_-]?key|access[_-]?token|password|passwd|pat|bearer)\b"
            r"[^\w\n]{0,4}['\"]?[A-Za-z0-9][A-Za-z0-9._-]{15,}"
        ),
    ),
]

# Advisory only — reported in the verdict, never redacted. Safe Harbor wants
# dates coarser than a year, but reporting periods and pipeline timestamps are
# legitimate in aggregate output, and the gate already forbids row grain.
_DAY_PRECISION_DATE = re.compile(
    r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/(?:19|20)?\d{2}\b"
)

_analyzer = None


def deterministic(text: str) -> tuple[str, list[str]]:
    """Regex redaction. Runs unconditionally, before and independent of NER."""
    kinds: list[str] = []
    for label, pattern in _DETERMINISTIC:
        text, n = pattern.subn(REDACT.format(label), text)
        if n:
            kinds.extend([label] * n)
    return text, kinds


class ScrubFail(Exception):
    """Structural check failed — nothing may be emitted."""


@dataclass
class ScrubReport:
    columns_denied: list[str] = field(default_factory=list)
    cells_suppressed: int = 0
    rows_suppressed: int = 0
    regex_hits: list[dict] = field(default_factory=list)
    ner_hits: list[dict] = field(default_factory=list)
    day_precision_dates: int = 0
    presidio_ran: bool = False

    @property
    def alarm(self) -> bool:
        """A hit on either identifier layer means the gate leaked."""
        return bool(self.regex_hits) or any("entities" in h for h in self.ner_hits)

    def to_dict(self) -> dict:
        return {
            "cells_suppressed": self.cells_suppressed,
            "rows_suppressed": self.rows_suppressed,
            "presidio_ran": self.presidio_ran,
            "alarm": self.alarm,
            "regex_hits": self.regex_hits[:50],
            "ner_hits": self.ner_hits[:50],
            "day_precision_dates": self.day_precision_dates,
        }


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine

        _analyzer = AnalyzerEngine()
    return _analyzer


# Presidio's PhoneRecognizer tops out at 0.4, so a 0.6 bar silently drops every
# phone number. Measured scores on this kind of data: phone 0.4, person 0.85.
_MIN_SCORE = 0.4


def _hits(text: str):
    return [
        x
        for x in _get_analyzer().analyze(text=text, entities=_NER_ENTITIES, language="en")
        if x.score >= _MIN_SCORE
    ]


def check_columns(
    columns: list[str], deny_patterns: list[str], allow_patterns: list[str] | None = None
) -> list[str]:
    """Structural check. Independent of the gate — catches what the gate missed."""
    allow = [p.lower() for p in allow_patterns or []]
    bad = []
    for col in columns:
        name = col.lower()
        if any(fnmatch(name, p) for p in allow):
            continue
        for pattern in deny_patterns:
            if fnmatch(name, pattern.lower()):
                bad.append(f"{col} (matched {pattern})")
                break
    return bad


def _is_count_col(name: str, patterns: list[str]) -> bool:
    n = name.lower()
    return any(fnmatch(n, p.lower()) for p in patterns)


def _small(value, k: int) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    try:
        n = float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return False
    return n == int(n) and 1 <= n < k


def _looks_numeric(rows: list[list], idx: int) -> bool:
    seen = False
    for row in rows[:200]:
        v = row[idx]
        if v is None:
            continue
        if isinstance(v, bool) or not (isinstance(v, (int, float)) or _NUMERIC.match(str(v))):
            return False
        seen = True
    return seen


def suppress(
    columns: list[str],
    rows: list[list],
    k: int,
    count_patterns: list[str],
    group_keys: set[str],
) -> tuple[int, int]:
    """k-anonymity suppression, in place. Returns (cells changed, rows hit).

    A row whose count falls below k has its measures suppressed too, not just
    the count — otherwise a mean or a sum over 3 patients still walks out.
    """
    count_idx = [i for i, c in enumerate(columns) if _is_count_col(c, count_patterns)]
    if not count_idx:
        return 0, 0
    keys = {g.lower() for g in group_keys}
    measure_idx = [
        i
        for i, c in enumerate(columns)
        if c.lower() not in keys and (i in count_idx or _looks_numeric(rows, i))
    ]

    changed = 0
    hit_rows = 0
    for row in rows:
        if not any(_small(row[i], k) for i in count_idx):
            continue
        hit_rows += 1
        for i in measure_idx:
            if row[i] != SUPPRESSED:
                row[i] = SUPPRESSED
                changed += 1
    return changed, hit_rows


def cell_scan(
    columns: list[str],
    rows: list[list],
    report: ScrubReport,
    ner_skip_columns: list[str] | None = None,
    run_ner: bool = True,
    budget: int = 400_000,
) -> None:
    """Redact every string cell in place. Two layers, deterministic first.

    The regex layer runs on EVERY cell, including allowlisted label columns —
    it has no false-positive problem, so there is no reason to exempt anything.

    The NER layer skips policy.yml's allow_columns. spaCy reads
    `ED Visits YTD 41822` and `Mercy General Hospital` as PERSON at 0.85, so
    scanning label columns produces nothing but false alarms — and an alarm
    that cries wolf gets ignored, which is the failure mode that matters. Those
    columns are already asserted non-human by the structural allowlist.
    """
    ner_skip = {
        i
        for i, c in enumerate(columns)
        if any(fnmatch(c.lower(), p.lower()) for p in ner_skip_columns or [])
    }
    if run_ner:
        _get_analyzer()
        report.presidio_ran = True

    spent = 0
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            if not isinstance(value, str) or len(value) < 3:
                continue

            cleaned, kinds = deterministic(value)
            if kinds:
                report.regex_hits.append(
                    {"row": r, "column": columns[c], "entities": sorted(set(kinds))}
                )
                row[c] = cleaned
                value = cleaned
            report.day_precision_dates += len(_DAY_PRECISION_DATE.findall(value))

            if not run_ner or c in ner_skip or _NUMERIC.match(value) or spent > budget:
                continue
            spent += len(value)
            found = _hits(value)
            if not found:
                continue
            entities = sorted({x.entity_type for x in found})
            report.ner_hits.append({"row": r, "column": columns[c], "entities": entities})
            row[c] = REDACT.format("+".join(entities))


def scrub(
    columns: list[str],
    rows: list[list],
    *,
    deny_columns: list[str],
    count_columns: list[str],
    allow_columns: list[str] | None = None,
    group_keys: set[str] | None = None,
    k: int = 11,
    require_presidio: bool = True,
    max_suppressed_share: float = 0.5,
) -> ScrubReport:
    report = ScrubReport()

    bad = check_columns(columns, deny_columns, allow_columns)
    if bad:
        report.columns_denied = bad
        raise ScrubFail(
            "Result set contains denied columns: "
            + "; ".join(bad)
            + ". Nothing was written. The gate should have caught this — fix policy.yml."
        )

    report.cells_suppressed, report.rows_suppressed = suppress(
        columns, rows, k, count_columns, group_keys or set()
    )

    # A grouping where most cells fall below k is a row dump wearing a GROUP BY.
    # Suppressing the measures is not enough — the group keys themselves are then
    # a near-unique list. Refuse the whole result rather than emit the keys.
    if rows and report.rows_suppressed / len(rows) > max_suppressed_share and len(rows) > 5:
        raise ScrubFail(
            f"{report.rows_suppressed} of {len(rows)} rows fell below k={k}. That grouping "
            "is fine-grained enough to be a row dump: suppressing the measures still "
            "leaves a near-unique list of group keys. Nothing was written — aggregate to "
            "a coarser grain."
        )

    try:
        cell_scan(columns, rows, report, ner_skip_columns=allow_columns, run_ner=True)
    except Exception as e:
        if require_presidio:
            raise ScrubFail(
                f"Presidio could not run ({type(e).__name__}: {e}) and require_presidio is "
                "on, so no output was written. Install the NER extra (`pip install "
                "phi-airgap[ner]`), or set require_presidio: false in config.yml to accept the "
                "gate alone."
            ) from e
        report.ner_hits.append({"error": f"{type(e).__name__}: {e}"})
        # The deterministic layer must still run — it is the floor.
        cell_scan(columns, rows, report, run_ner=False)

    return report


def scrub_text(text: str, run_ner: bool = True) -> tuple[str, list[str], list[str]]:
    """Scrub free text (dbt stdout, a PR diff, a pasted log).

    Returns (scrubbed_text, deterministic_kinds, ner_kinds) — kept separate on
    purpose. Deterministic hits are unambiguous and worth failing a gate on;
    spaCy's PERSON fires on ordinary prose (tool names, release names), so
    treating the two the same produces a check that always fails and therefore
    gets ignored.

    The deterministic layer always runs; NER is best-effort on top, so a broken
    spaCy install degrades this to regex-only rather than to nothing.
    """
    det_kinds: list[str] = []
    ner_kinds: list[str] = []
    out = []
    for line in text.splitlines(keepends=True):
        line, det = deterministic(line)
        det_kinds.extend(det)
        if not run_ner or len(line.strip()) < 3:
            out.append(line)
            continue
        try:
            found = _hits(line)
        except Exception:
            run_ner = False
            out.append(line)
            continue
        if not found:
            out.append(line)
            continue
        for x in sorted(found, key=lambda r: r.start, reverse=True):
            ner_kinds.append(x.entity_type)
            line = line[: x.start] + REDACT.format(x.entity_type) + line[x.end :]
        out.append(line)
    return "".join(out), sorted(set(det_kinds)), sorted(set(ner_kinds))
