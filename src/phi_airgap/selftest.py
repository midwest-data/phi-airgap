"""Red-team the gate, the scrubber and the harness hook.

Run:  phi-airgap selftest     (or: pytest tests/)
Needs sqlglot + PyYAML; no network, no token. The Presidio cases are exercised
by the scrubber's own tests; the deterministic layer here needs no NER.

Every DENY case here is a habit this phi-airgap exists to kill. If one of them ever
returns ALLOW, the phi-airgap is broken — do not weaken the case, fix the policy.

The relations below are GENERIC examples matching policy.example.yml:
  raw.* / staging.* / *patient* / *encounter*     -> RED
  analytics.* / analytics_dev.*                    -> AMBER
  reporting.* / *.agg_* / *.metric_targets         -> GREEN
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from . import gate, scrub, util

POLICY = yaml.safe_load((util.DATA / "policy.example.yml").read_text())
HOOK = util.DATA / "pretool-phi-airgap.py"

# Config the hook subprocess reads (via PHI_AIRGAP_CONFIG), giving it a concrete
# warehouse host and one readable Keychain service so both the HTTP block and
# the credential carve-out are exercised.
HOST = "test-warehouse.example.com"
READABLE_SERVICE = "phi-airgap-issues-key"

DENY = [
    # The three core red-team cases.
    "select * from raw.vendor.fact_visit limit 10",
    "select order_epic_id, count(*) from analytics_dev.marts.fct_orders group by 1",
    "select patient_id from analytics_dev.marts.patient_trajectory group by 1",
    # Row peeks in every disguise.
    "select * from analytics.marts.patient_trajectory",
    "select a.* from raw.vendor.enc a join raw.vendor.person b on a.enc_id = b.enc_id",
    "select admit_ts, department_name from analytics_dev.dev_g__marts.patient_trajectory limit 5",
    # Identifiers hidden in a predicate or an ordering, not the projection.
    "select count(*) from analytics.ed.ed_visits where mrn = '12345'",
    "select count(*) as n from analytics.core.encounter_fact order by patient_id",
    # An unclassified relation must fail closed.
    "select * from some_new_catalog.some_schema.some_table",
    # Not read-only.
    "drop table analytics_dev.dev_g.scratch",
    "insert into analytics_dev.dev_g.scratch select 1",
    "update analytics_dev.dev_g.scratch set x = 1",
    # Two statements in one file.
    "select count(*) as n from reporting.metrics.agg_visits_month; select 1",
    # R1: a path read has no relation name, so classification never ran and
    #     every downstream rule was skipped. This was a total bypass.
    "select * from read_files('abfss://c@s.dfs.core.windows.net/raw/*.parquet')",
    "select * from parquet.`/mnt/raw/people`",
    "select count(*) as n from delta.`abfss://c@s.dfs.core.windows.net/p`",
    "select * from json.`/mnt/raw/people.json`",
    # R4: DISTINCT is a de-duplicated row dump with no count to suppress.
    "select distinct dept_id from analytics.core.encounter_fact",
    "select distinct admit_ts, dept_id from analytics_dev.marts.patient_trajectory",
    # R5: window functions preserve row count — not aggregation.
    "select max(los_days) over (partition by dept_id) as m from analytics.core.encounter_fact",
    "select row_number() over (order by admit_ts) as rn from analytics.core.encounter_fact",
    # R6: an aggregate with no count column cannot be k-suppressed, so
    #     avg(los) over a group of three is three patients' data.
    "select dept_id, avg(los_days) as avg_los from analytics.core.encounter_fact group by 1",
    "select sum(net_revenue) as rev from analytics.costs.gl_detail",
    # R7: OFFSET paging is the same peek, repeated.
    "select dept_id from analytics.core.encounter_fact limit 10 offset 200",
    # A high-cardinality group key still dodges k-anon if the key survives;
    # denied here because there is no aggregate at all (R6a).
    "select external_id from raw.vendor.person_dim group by 1",
    # `select *` that cannot be screened must fail closed, even on GREEN: with
    # no metadata cache the gate has no idea what columns come back.
    "select * from reporting.metrics.agg_lwbs_month",
    # R8: value-preserving "aggregates" return row values, not a statistic.
    "select dept_id, collect_list(diagnosis_text) as dx, count(*) as n "
    "from raw.vendor.fact_visit group by 1",
    "select dept_id, collect_set(diagnosis_text) as dx, count(*) as n "
    "from raw.vendor.fact_visit group by 1",
    "select dept_id, any_value(external_id) as x, count(*) as n "
    "from raw.vendor.fact_visit group by 1",
    "select dept_id, first(diagnosis_text) as dx, count(*) as n "
    "from raw.vendor.fact_visit group by 1",
    "select dept_id, array_agg(external_id) as ids, count(*) as n "
    "from analytics.core.encounter_fact group by 1",
    # R6: an arithmetic count wears a count-like name but defeats k-anon.
    "select external_id, count(*) * 100 as n from raw.vendor.fact_visit group by 1",
    "select external_id, count(*) + 10 as n from raw.vendor.fact_visit group by 1",
]

ALLOW = [
    # A GREEN pre-aggregated mart, aggregation-exempt.
    """
    select entity_name, sum(infection_count) as infections
    from reporting.quality.agg_infections_month
    where metric_year = 2025
    group by entity_name
    """,
    # Aggregate over a RED table is the sanctioned way to touch raw data.
    "select date_trunc('month', admit_ts) as mth, count(*) as encounters "
    "from raw.vendor.encounter_fact group by 1",
    # Debugging a join without looking at rows.
    "select count(*) as n, count(distinct order_key) as order_key_n "
    "from analytics_dev.marts.fct_orders",
    # GREEN marts are exempt from the aggregation requirement.
    "select metric_name, actual, target from reporting.targets.metric_targets limit 20",
    # A count column satisfies R6, and window functions are fine on GREEN.
    "select dept_id, count(*) as n, avg(los_days) as avg_los "
    "from analytics.core.encounter_fact group by 1",
    "select entity_name, rank() over (order by actual desc) as rk "
    "from reporting.targets.metric_targets",
    # Aggregating an inner raw scan is the sanctioned shape: only the outer
    # projection leaves the boundary.
    "with raw_scan as (select dept_id, los_days from analytics.core.encounter_fact) "
    "select dept_id, count(*) as n, avg(los_days) as avg_los from raw_scan group by 1",
    # green-beats-amber: an `agg_` carve-out that physically lives inside the
    # AMBER mart catalog is still GREEN, so it is exempt from aggregation.
    "select entity_name, actual from analytics_dev.marts.agg_orders_month limit 20",
    # A count under any alias satisfies R6 — and the scrubber suppresses on it
    # (see _suppression), because the verdict carries the alias.
    "select dept_id, count(*) as total_people from raw.vendor.fact_visit group by 1",
    # min/max are legitimate on timestamps (documented residual on free text).
    "select dept_id, max(admit_ts) as last_admit, count(*) as n "
    "from raw.vendor.fact_visit group by 1",
]


def _suppression() -> list[str]:
    """k-anonymity: a cell below 11 is suppressed, and so are its measures."""
    fails = []
    cols = ["entity_name", "infection_count", "rate_per_1000"]
    rows = [["North", 13, 0.42], ["South", 3, 1.10], ["East", 0, 0.0]]
    changed, hit = scrub.suppress(cols, rows, 11, POLICY["count_columns"], {"entity_name"})
    if rows[0] != ["North", 13, 0.42]:
        fails.append(f"SUPPRESS touched a healthy row: {rows[0]}")
    if rows[1] != ["South", scrub.SUPPRESSED, scrub.SUPPRESSED]:
        fails.append(f"SUPPRESS should blank count and measure: {rows[1]}")
    if rows[2] != ["East", 0, 0.0]:
        fails.append("SUPPRESS: a true zero is not a small cell")
    if (changed, hit) != (2, 1):
        fails.append(f"SUPPRESS counted {(changed, hit)}, expected (2, 1)")

    # The structural column check is independent of the gate.
    if not scrub.check_columns(["patient_name"], POLICY["deny_columns"], POLICY["allow_columns"]):
        fails.append("CHECK_COLUMNS should deny patient_name")
    if scrub.check_columns(["metric_name"], POLICY["deny_columns"], POLICY["allow_columns"]):
        fails.append("CHECK_COLUMNS should allow metric_name")

    # `count(*) as total_people` matches no count_columns pattern; the gate's
    # verdict must carry the alias so the scrubber still suppresses on it.
    sql = "select dept_id, count(*) as total_people from raw.vendor.fact_visit group by 1"
    v = gate.check(sql, POLICY)
    if v.count_cols != {"total_people"}:
        fails.append(f"GATE count_cols should be {{'total_people'}}, got {v.count_cols}")
    rows = [["ED", 40], ["ICU", 4]]
    scrub.suppress(
        ["dept_id", "total_people"], rows, 11, [*POLICY["count_columns"], *v.count_cols],
        v.group_keys,
    )
    if rows[1] != ["ICU", scrub.SUPPRESSED]:
        fails.append(f"SUPPRESS should blank total_people < 11 via verdict.count_cols: {rows}")
    return fails


def _star_screening() -> list[str]:
    """`select *` must be screened against the metadata cache, not waved through."""
    fails = []
    index = {
        "reporting.metrics.agg_visits_month": {
            "columns": {"entity_name": {"type": "string", "description": "Reporting entity"},
                        "patient_name": {"type": "string", "description": "Patient full name"}}
        },
        "reporting.metrics.agg_orders_month": {
            "columns": {"entity_name": {"type": "string", "description": "Reporting entity"},
                        "ptnt_nm_1": {"type": "string", "description": "Patient's legal name"}}
        },
    }
    # A denied column reached only via `*` on a GREEN table.
    v = gate.check("select * from reporting.metrics.agg_visits_month", POLICY, index)
    if v.allowed:
        fails.append("GATE should DENY: `*` hiding patient_name on a GREEN table")
    # An opaque name whose DESCRIPTION gives it away.
    v = gate.check("select ptnt_nm_1 from reporting.metrics.agg_orders_month", POLICY, index)
    if v.allowed:
        fails.append("GATE should DENY: opaque column name with an identifier description")
    # The same table without the identifier column is fine.
    v = gate.check("select entity_name from reporting.metrics.agg_orders_month", POLICY, index)
    if not v.allowed:
        fails.append(f"GATE should ALLOW: entity_name on GREEN -> {v.reasons}")
    # `select *` on a clean GREEN table, screened against the cache, is fine.
    clean = {"reporting.metrics.agg_lwbs_month": {
        "columns": {"entity_name": {"type": "string", "description": "Reporting entity"},
                    "actual": {"type": "double", "description": "Metric value"}}}}
    v = gate.check("select * from reporting.metrics.agg_lwbs_month", POLICY, clean)
    if not v.allowed:
        fails.append(f"GATE should ALLOW: screened `*` on a clean GREEN table -> {v.reasons}")
    return fails


def _deterministic_redaction() -> list[str]:
    """The regex layer must catch what Presidio measurably misses."""
    fails = []
    cases = [
        ("ssn 123-45-6789", "US_SSN"),
        ("call 330-555-0142", "PHONE_NUMBER"),
        ("m.gonzalez@example.com", "EMAIL_ADDRESS"),
        ("MRN 1234567", "RECORD_NUMBER"),
        ("CSN: 987654321", "RECORD_NUMBER"),
        ("token ghp_3m2irMIabcdefghijklmnopqrstuvwxyz12", "TOKEN"),
        ("host 10.4.22.19", "IP_ADDRESS"),
    ]
    for text, expected in cases:
        cleaned, kinds = scrub.deterministic(text)
        if expected not in kinds:
            fails.append(f"REGEX should redact {expected} in {text!r}, got {kinds}")
            continue
        # The sensitive digits/handle must be gone, not merely flagged.
        secret = text.split()[-1].rstrip(".")
        if secret in cleaned:
            fails.append(f"REGEX flagged but did not remove {secret!r}: {cleaned!r}")
    # Must NOT eat legitimate aggregate figures.
    for safe in ["3186327", "41822", "13", "2025-07", "Mercy General Hospital", "1.42"]:
        cleaned, kinds = scrub.deterministic(safe)
        if kinds:
            fails.append(f"REGEX false positive on {safe!r}: {kinds}")
    return fails


def _adopt_roundtrip() -> list[str]:
    """`phi-airgap adopt` rewrites the file holding the only copy of a live token.

    It gets tested on a throwaway service with a fake secret, because 'it
    probably works' is not good enough for that operation. macOS-only (Keychain);
    skipped where the `security` CLI is unavailable.
    """
    if not shutil.which("security"):
        return []  # Keychain is macOS-specific; nothing to test here.

    from argparse import Namespace

    from phi_airgap import cli, util

    fails = []
    service = "phi-airgap-selftest-throwaway"
    secret = "abcdef0123456789abcdef0123456789abcd"
    body = (
        "# local dev\nDATABRICKS_HOST=example.cloud.databricks.com\n"
        f"DATABRICKS_TOKEN={secret}\nTABLE_X=analytics.a.b\n"
    )
    with tempfile.TemporaryDirectory() as d:
        env = Path(d) / ".env"
        env.write_text(body)
        try:
            rc = cli.cmd_adopt(
                Namespace(file=str(env), key="DATABRICKS_TOKEN", service=service)
            )
            if rc != 0:
                fails.append(f"ADOPT returned {rc}")
            after = env.read_text()
            if secret in after:
                fails.append("ADOPT left the secret in the file")
            if "DATABRICKS_HOST=example.cloud.databricks.com" not in after:
                fails.append("ADOPT clobbered unrelated lines")
            if "TABLE_X=analytics.a.b" not in after:
                fails.append("ADOPT dropped trailing lines")
            if service not in after:
                fails.append("ADOPT wrote no pointer to the Keychain service")
            backup = env.with_suffix(env.suffix + ".pre-airgap")
            if not backup.exists() or secret not in backup.read_text():
                fails.append("ADOPT did not leave a recoverable backup")
            if util.keychain_get(service) != secret:
                fails.append("ADOPT did not store the secret retrievably")
        except SystemExit as e:
            fails.append(f"ADOPT exited: {e}")
        finally:
            subprocess.run(
                ["security", "delete-generic-password", "-a", getpass.getuser(),
                 "-s", service],
                capture_output=True,
            )
    return fails


def _cardinality_refusal() -> list[str]:
    """A grouping where most cells fall below k must be refused outright."""
    fails = []
    cols = ["external_id", "n"]
    rows = [[f"id{i}", 1] for i in range(20)]
    try:
        scrub.scrub(
            cols, rows, deny_columns=POLICY["deny_columns"],
            count_columns=POLICY["count_columns"], allow_columns=POLICY["allow_columns"],
            group_keys={"external_id"}, k=11, require_presidio=False,
        )
        fails.append("SCRUB should refuse a result where 20/20 rows fall below k")
    except scrub.ScrubFail:
        pass
    # A normal aggregate result must survive.
    cols = ["entity_name", "n"]
    rows = [["North", 4102], ["South", 880], ["East", 231], ["West", 12]]
    try:
        r = scrub.scrub(
            cols, rows, deny_columns=POLICY["deny_columns"],
            count_columns=POLICY["count_columns"], allow_columns=POLICY["allow_columns"],
            group_keys={"entity_name"}, k=11, require_presidio=False,
        )
        if r.rows_suppressed:
            fails.append(f"SCRUB suppressed a healthy aggregate result: {rows}")
    except scrub.ScrubFail as e:
        fails.append(f"SCRUB should allow a healthy aggregate result: {e}")
    return fails


def _ner_smoke() -> list[str]:
    """When the [ner] extra is installed, Presidio must actually redact a name.

    Skipped on a core-only install (the NER cases run in the [ner] CI job).
    """
    try:
        import presidio_analyzer  # noqa: F401
    except Exception:
        return []
    fails = []
    cleaned, _det, ner = scrub.scrub_text("Contact Jane Doe about the ticket")
    if "PERSON" not in ner:
        fails.append(f"NER should flag PERSON in a name, got {ner}")
    if "Jane Doe" in cleaned:
        fails.append(f"NER flagged but did not redact the name: {cleaned!r}")
    return fails


HOOK_DENY = [
    'python3 -c "from databricks import sql"',
    "cat .envrc",
    "cat ./.env",
    "cat .env",
    "cat dir/.env",
    "cat sub/nested/.env",
    "head -5 ../.env",
    # .env.pre-airgap is `phi-airgap adopt`'s backup and still holds the pre-airgap token.
    "cat .env.pre-airgap",
    "cat .env.local",
    "databricks sql query --warehouse x",
    "dbt show --select fct_orders",
    "phi-airgap dbt show --select fct_orders",
    "dbt run-operation print_table",
    'security find-generic-password -a "$USER" -s phi-airgap-databricks-pat -w',
    'security find-generic-password -a "$USER" -s phi-airgap-github-pat -w',
    f"curl -H 'Authorization: Bearer x' https://{HOST}/api/2.0/sql",
    "phi-airgap run .phi-airgap/q.sql",
    # Command substitution must still be segmented.
    "x=$(dbsql query 'select 1')",
    "echo `databricks sql query`",
    "phi-airgap adopt .env DATABRICKS_TOKEN",
    "phi-airgap refresh",
    "phi-airgap refresh --draft-policy",
    "echo TOKEN=x >> .env",
    'python3 -c "import duckdb; duckdb.sql(\'select * from x.parquet\')"',
    # Wrappers hide the command-position token; they are peeled, not patched.
    "uv run phi-airgap run .phi-airgap/q.sql",
    "uvx phi-airgap run q.sql",
    "python3 -m phi_airgap.cli run q.sql",
    "python3 -m phi_airgap run q.sql",
    'env python3 -c "from databricks import sql"',
    'bash -c "databricks sql query --warehouse x"',
    'sh -lc "phi-airgap adopt .env DATABRICKS_TOKEN"',
    "timeout 30 databricks sql query",
    "uv run dbt show --select fct_orders",
    'nice -n 5 uv run --python 3.12 python3 -c "import duckdb"',
    "xargs phi-airgap run",
    "poetry run phi-airgap refresh",
    'uv run --with x python3 - <<PY\nimport databricks.sql\nPY',
    # The control plane: the policy is the ACL; the human edits it.
    "sed -i 's/red/green/' ~/.phi-airgap/policy.yml",
    "echo 'red: []' > ~/.phi-airgap/policy.yml",
    "cp mine.yml ~/.phi-airgap/config.yml",
    "tee ~/.claude/settings.json < new.json",
    "rm ~/.claude/hooks/pretool-phi-airgap.py",
    "chmod 000 ~/.claude/hooks/pretool-phi-airgap.py",
    "mv x.py ~/.claude/hooks/pretool-phi-airgap.py",
]

HOOK_ALLOW = [
    "git status",
    "cd project && uv run pytest",
    "phi-airgap schema fct_orders",
    "phi-airgap check .phi-airgap/q.sql",
    "phi-airgap dbt run --select marts__fct_orders",
    "phi-airgap dbt test --select agg_infections_month",
    "phi-airgap doctor",
    "phi-airgap log --tail 20",
    "gh pr view 149",
    'python3 -c "print(1+1)"',
    "cat .env.example",
    "cat sub/.env.template",
    # The one readable Keychain service — reaches no sensitive data.
    f'security find-generic-password -a "$USER" -s {READABLE_SERVICE} -w',
    "dbt compile --select agg_infections_month",
    # Quoting: a `|` inside a quoted regex is not a pipe.
    "grep -nE '^## |verif|databricks|dbt ' notes.md",
    "rg 'databricks|duckdb' --type md",
    "phi-airgap refresh --offline",
    "phi-airgap refresh --offline --draft-policy",
    # Incidental mentions: writing docs about the phi-airgap is not executing it.
    "git commit -m 'document phi-airgap refresh and env file removal'",
    # PROSE about the carve-out must not parse as a path and get denied.
    "git commit -m 'the .env carve-out and the .env.pre-airgap backup'",
    "printf '%s' '- [Airgap notes](phi-airgap-notes.md)' >> MEMORY.md",
    "grep -rn 'DATABRICKS_TOKEN' --include='*.md' docs/",
    # A heredoc body that merely mentions `.env` is data, not a read.
    'python3 - <<PY\nimport os\nprint(".env")\nPY',
    # Wrapped ALLOW commands stay allowed once unwrapped.
    "uv run phi-airgap check .phi-airgap/q.sql",
    "timeout 5 phi-airgap doctor",
    'bash -c "git log --oneline"',
    # Reading the control plane is fine; only writing it is the human's.
    "cat ~/.phi-airgap/policy.yml",
    "sed -n 1,20p ~/.phi-airgap/config.yml",
    "echo hi > notes.md",
]

HOOK_READ_DENY = [
    "/Users/x/project/.envrc",
    "/Users/x/project/.env",
    "/Users/x/project/sub/.env",
    "/Users/x/project/config/.env",
    "/Users/x/project/.env.pre-airgap",
    "/Users/x/project/.env.local",
    "/Users/x/data/extract.parquet",
    "/Users/x/exports/q.parquet",
    "/Users/x/warehouse.duckdb",
    "/Users/x/project/.phi-airgap/out/q.raw.csv",
]

HOOK_READ_ALLOW = [
    "/Users/x/project/.phi-airgap/out/q.csv",
    "/Users/x/project/.phi-airgap/out/q.json",
    "/Users/x/project/.env.example",
    "/Users/x/project/sub/.env.template",
    "/Users/x/project/models/agg_infections_month.sql",
    "/Users/x/.phi-airgap/policy.yml",
]

# Write/Edit/MultiEdit share the Read rules plus the control-plane files.
HOOK_WRITE_DENY = [
    "/Users/x/project/.env",
    "/Users/x/project/.envrc",
    "/Users/x/.phi-airgap/policy.yml",
    "/Users/x/.phi-airgap/config.yml",
    "/Users/x/.claude/hooks/pretool-phi-airgap.py",
    "/Users/x/.claude/settings.json",
]

HOOK_WRITE_ALLOW = [
    "/Users/x/project/.env.example",
    "/Users/x/project/.phi-airgap/q.sql",
    "/Users/x/project/models/agg_x.sql",
    "/Users/x/project/.claude/settings.local.json",
]


class _FakeCursor:
    def __init__(self, columns, rows):
        self.description = [(c,) for c in columns]
        self._rows = rows

    def execute(self, sql):
        pass

    def fetchmany(self, n):
        return self._rows[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakeConn:
    def __init__(self, columns, rows):
        self._c = _FakeCursor(columns, rows)

    def cursor(self):
        return self._c

    def close(self):
        pass


def _run_end_to_end() -> list[str]:
    """`phi-airgap run` with a stub adapter: suppression, row ceiling, ScrubFail,
    and the policy-changed banner. No network."""
    import contextlib
    import io

    from . import adapters, run

    fails = []
    canned: dict = {}
    fake = type("A", (), {"connect": staticmethod(lambda cfg: _FakeConn(**canned))})
    adapters.register("fake", fake)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "policy.yml").write_text((util.DATA / "policy.example.yml").read_text())
        (d / "config.yml").write_text(
            "adapter: fake\nrequire_presidio: false\nmax_rows_sensitive: 5\n"
        )
        old = (util.CONFIG_FILE, util.POLICY_FILE, os.environ.get("PHI_AIRGAP_ROOT"))
        util.CONFIG_FILE, util.POLICY_FILE = d / "config.yml", d / "policy.yml"
        os.environ["PHI_AIRGAP_ROOT"] = str(d)
        q = d / "q.sql"
        q.write_text(
            "select dept_id, count(*) as total_people from raw.vendor.fact_visit group by 1"
        )
        try:
            def go(columns, rows):
                canned.update(columns=columns, rows=rows)
                err, out = io.StringIO(), io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                    rc = run.run_file(q)
                return rc, out.getvalue() + err.getvalue()

            # ALLOW, with `total_people` suppressed below k even though it matches
            # no count_columns pattern.
            rc, text = go(["dept_id", "total_people"], [["ED", 40], ["ICU", 4]])
            csv_out = (d / ".phi-airgap" / "out" / "q.csv").read_text()
            if rc != 0:
                fails.append(f"RUN should ALLOW, rc={rc}: {text[-300:]}")
            elif "ICU,<11" not in csv_out:
                fails.append(f"RUN should suppress total_people<11, csv: {csv_out!r}")
            # Row ceiling: refused, not truncated.
            rc, text = go(["dept_id", "total_people"], [[f"d{i}", 100] for i in range(9)])
            if rc != 5 or (d / ".phi-airgap" / "out" / "q.csv").exists():
                fails.append(f"RUN should refuse over the row ceiling with rc=5, got {rc}")
            # ScrubFail: a denied column that the gate somehow missed.
            rc, text = go(["dept_id", "patient_name", "total_people"], [["ED", "x", 40]])
            if rc != 4:
                fails.append(f"RUN should ScrubFail on a denied result column with rc=4, got {rc}")
            # Policy-changed banner after the ACL is touched.
            (d / "policy.yml").write_text((d / "policy.yml").read_text() + "\n# touched\n")
            rc, text = go(["dept_id", "total_people"], [["ED", 40]])
            if "POLICY CHANGED since last run" not in text:
                fails.append("RUN should print the POLICY CHANGED banner after a policy edit")
        finally:
            util.CONFIG_FILE, util.POLICY_FILE = old[0], old[1]
            if old[2] is None:
                os.environ.pop("PHI_AIRGAP_ROOT", None)
            else:
                os.environ["PHI_AIRGAP_ROOT"] = old[2]
    return fails


def _hook(payload: dict, env: dict) -> bool:
    """True if the hook denies."""
    r = subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(payload),
        capture_output=True, text=True, env=env,
    )
    return '"deny"' in r.stdout


def main() -> int:
    fails = []

    for sql in DENY:
        v = gate.check(sql, POLICY)
        if v.allowed:
            fails.append(f"GATE should DENY but allowed: {sql.strip()[:90]}")

    for sql in ALLOW:
        v = gate.check(sql, POLICY)
        if not v.allowed:
            fails.append(f"GATE should ALLOW but denied: {sql.strip()[:70]} -> {v.reasons}")

    fails += _suppression()
    fails += _star_screening()
    fails += _deterministic_redaction()
    fails += _cardinality_refusal()
    fails += _adopt_roundtrip()
    fails += _ner_smoke()
    fails += _run_end_to_end()

    if HOOK.exists():
        # Give the hook subprocess a config with a concrete host + readable service.
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "config.yml"
            cfg.write_text(
                f"host: {HOST}\nreadable_keychain_service: {READABLE_SERVICE}\n"
            )
            env = {**os.environ, "PHI_AIRGAP_CONFIG": str(cfg)}
            for cmd in HOOK_DENY:
                if not _hook({"tool_name": "Bash", "tool_input": {"command": cmd}}, env):
                    fails.append(f"HOOK should DENY Bash: {cmd}")
            for cmd in HOOK_ALLOW:
                if _hook({"tool_name": "Bash", "tool_input": {"command": cmd}}, env):
                    fails.append(f"HOOK should ALLOW Bash: {cmd}")
            for p in HOOK_READ_DENY:
                if not _hook({"tool_name": "Read", "tool_input": {"file_path": p}}, env):
                    fails.append(f"HOOK should DENY Read: {p}")
            for p in HOOK_READ_ALLOW:
                if _hook({"tool_name": "Read", "tool_input": {"file_path": p}}, env):
                    fails.append(f"HOOK should ALLOW Read: {p}")
            # Grep takes `path`; the same rules apply.
            grep = {"tool_name": "Grep", "tool_input": {"pattern": "T", "path": "/x/.env"}}
            if not _hook(grep, env):
                fails.append("HOOK should DENY Grep on .env")
            for tool in ("Write", "Edit", "MultiEdit"):
                for p in HOOK_WRITE_DENY:
                    if not _hook({"tool_name": tool, "tool_input": {"file_path": p}}, env):
                        fails.append(f"HOOK should DENY {tool}: {p}")
                for p in HOOK_WRITE_ALLOW:
                    if _hook({"tool_name": tool, "tool_input": {"file_path": p}}, env):
                        fails.append(f"HOOK should ALLOW {tool}: {p}")
    else:
        fails.append(f"hook not installed at {HOOK}")

    total = sum(
        map(len, (DENY, ALLOW, HOOK_DENY, HOOK_ALLOW, HOOK_READ_DENY, HOOK_READ_ALLOW))
    ) + 3 * (len(HOOK_WRITE_DENY) + len(HOOK_WRITE_ALLOW)) + 1
    for f in fails:
        print(f"FAIL  {f}")
    print(f"\n{total - len(fails)}/{total} cases pass" + (" — PHI-AIRGAP OK" if not fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
