import sys
from unittest.mock import MagicMock

import pytest

from phi_airgap import gate, meta, run, util
from phi_airgap.adapters import get_adapter

INDEX = {
    "public.user": {
        "row_count": 1000,
        "columns": {
            "language": {"type": "text", "distinct_count": 5},
            "email": {"type": "text", "distinct_count": 1000},
            "created_at": {"type": "timestamp"},
        },
    },
    "public.user_language": {
        "row_count": 1000,
        "columns": {
            "self_level": {"type": "text"},
            "fluency_score": {"type": "numeric"},
            "total_reps": {"type": "integer"},
        },
    },
    "public.prompt_skill": {"row_count": 1000, "columns": {"skill": {"type": "text"}}},
    "ops_ro.daily": {"row_count": 1000, "columns": {"language": {"type": "text"}}},
}


def test_postgres_session(monkeypatch):
    driver = MagicMock()
    driver.connect.return_value.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        False,
    )
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    monkeypatch.setenv("TEST_PG_DSN", "test-only-dsn")
    assert (
        get_adapter("postgres").connect({"dsn_env": "TEST_PG_DSN", "statement_timeout": "7s"})
        is driver.connect.return_value
    )
    driver.connect.assert_called_once_with(
        "test-only-dsn",
        autocommit=True,
        options="-c default_transaction_read_only=on -c statement_timeout=7s",
    )
    monkeypatch.setenv("PHI_AIRGAP_PG_DSN", "default-test-dsn")
    get_adapter("postgres").connect({})
    assert driver.connect.call_args.kwargs["options"].endswith("statement_timeout=15s")


def test_postgres_missing_env(monkeypatch, capsys):
    monkeypatch.delenv("PHI_AIRGAP_PG_DSN", raising=False)
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect({})
    assert "unset" in capsys.readouterr().err


def test_postgres_failures_are_safe(monkeypatch, capsys):
    monkeypatch.setenv("PHI_AIRGAP_PG_DSN", "private-test-dsn")
    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect({})
    assert "phi-airgap[postgres]" in capsys.readouterr().err
    driver = MagicMock()
    driver.connect.side_effect = RuntimeError("private-test-dsn")
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect({})
    assert "private-test-dsn" not in capsys.readouterr().err
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect(
            {"statement_timeout": "0 -c default_transaction_read_only=off"}
        )
    assert driver.connect.call_count == 1


def test_postgres_metadata_and_stats(monkeypatch):
    monkeypatch.setattr(util, "config", lambda: {"adapter": "postgres", "sql_dialect": "postgres"})
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = [("db", "public", "user", "language", "text", None)]
    cm = MagicMock()
    cm.__enter__.return_value = conn
    monkeypatch.setattr(run, "connect", lambda: cm)
    index = meta._from_information_schema(["public"])
    assert index == {"public.user": {"columns": {"language": {"type": "text", "description": ""}}}}
    assert cur.execute.call_args.args[1] == ("public",)
    fetch = MagicMock(return_value=([], [[25, 3]]))
    monkeypatch.setattr(run, "fetch", fetch)
    assert meta.add_stats(conn, index, list(index)) == 1
    assert (
        fetch.call_args.args[1]
        == 'select count(*), count(distinct "language") from "public"."user"'
    )
    assert index["public.user"]["row_count"] == 25


def test_postgres_gate(monkeypatch):
    monkeypatch.setattr(util, "config", lambda: {**util.DEFAULT_CONFIG, "sql_dialect": "postgres"})
    policy = {"red": ["public.user"], "deny_columns": ["email", "id"], "count_columns": ["n"]}
    assert gate.check(
        'select language, count(*) as n from public."user" group by language', policy, INDEX
    ).allowed
    assert not gate.check('select email from public."user" limit 1', policy).allowed


ATTACKS = {
    "tableless_query_to_xml": (
        "select query_to_xml('select * from public.\"user\" limit 150', true, false, '') as x"
    ),
    "tableless_xml_text": (
        "select cast(query_to_xml('select * from public.\"user\"', true, false, '') as text) as x"
    ),
    "tableless_readfile": (
        "select pg_read_file('/etc/passwd') as f, current_setting('data_directory') as d"
    ),
    "tableless_dblink": "select dblink_exec('dbname=x', 'delete from t') as r",
    "tableless_terminate": "select pg_terminate_backend(pid) as r from pg_stat_activity",
    "rowcast_crossjoin": (
        'select count(*) as n, u::text as r from public."user" u cross join pub'
        'lic."user" v group by u::text'
    ),
    "rowjson_join": (
        'select to_jsonb(u)::text as r, count(*) as n from public."user" u join'
        " public.prompt_skill p on true group by 1"
    ),
    "rowcast_paged": (
        'select count(*) as n, u::text as r from public."user" u cross join pub'
        "lic.prompt_skill v group by u::text order by 2 limit 150 offset 150"
    ),
    "pg_stats_mcv": (
        "select s.most_common_vals::text as v, count(*) as n from pg_stats s cr"
        "oss join public.prompt_skill p group by 1"
    ),
    "scalar_sub_key": (
        'select (select u::text from public."user" u offset 5 limit 1) as r, co'
        "unt(*) as n from public.prompt_skill group by 1"
    ),
    "cte_delete": (
        "with d as (delete from public.prompt_skill returning 1) select count(*) as n from d"
    ),
    "select_into": "select count(*) as n into public.zz from public.prompt_skill",
    "for_update": "select count(*) as n from public.prompt_skill for update",
    "show_all": "show all",
    "sleep_where": "select count(*) as n from public.prompt_skill where pg_sleep(100) is null",
    "green_plus_fn": (
        "select query_to_xml('select * from public.\"user\"', true, false, '') as"
        " x from ops_ro.daily"
    ),
    "email_denied": 'select email, count(*) as n from public."user" group by 1',
    "setconfig": "select set_config('default_transaction_read_only','off',false) as s",
    "explain": "explain analyze delete from public.prompt_skill",
    "copy": 'copy (select * from public."user") to stdout',
    "json_fn": (
        "select jsonb_extract_path_text(profile, 'email') as e, count(*) as n f"
        'rom public."user" cross join public.prompt_skill group by 1'
    ),
    "lo": "select lo_get(1) as x",
}

ATTACKS.update(
    {
        "cte_self_join": (
            'with u as (select language from public."user") '
            "select language, count(*) as n from u cross join u v group by language"
        ),
        "whole_row": 'select u::text, count(*) as n from public."user" u group by u::text',
        "self_join": 'select count(*) as n from public."user" u cross join public."user" v',
        "information_schema": "select count(*) as n from information_schema.columns",
        "qualified_builtin": "select public.count(*) as n from public.prompt_skill",
        "unknown_function": "select mystery(language), count(*) as n from public.users group by 1",
    }
)


@pytest.mark.parametrize("sql", ATTACKS.values(), ids=ATTACKS.keys())
def test_postgres_security_denials(sql):
    policy = {
        "green": ["ops_ro.*", "pg_*", "information_schema.*"],
        "deny_columns": ["email", "id"],
        "count_columns": ["n"],
    }
    verdict = gate.check(sql, policy, INDEX, dialect_name="postgres")
    assert not verdict.allowed, sql


@pytest.mark.parametrize(
    "expression",
    [
        "lower(language)",
        "upper(language)",
        "coalesce(language, 'unknown')",
        "cast(language as text)",
        "case when language = 'es' then 'es' else 'other' end",
    ],
)
def test_postgres_group_key_expressions_denied(expression):
    # Round 7: a group key is a bare column or a month/quarter/year truncation;
    # any expression can pad a target row (`group by x in (a, b)`).
    sql = f'select {expression}, count(*) as n from public."user" group by 1'
    assert not gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres").allowed


@pytest.mark.parametrize("result", [(True,), None])
def test_postgres_unsafe_role(monkeypatch, capsys, result):
    driver = MagicMock()
    conn = driver.connect.return_value
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = result
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    monkeypatch.setenv("PHI_AIRGAP_PG_DSN", "private-test-dsn")
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect({})
    conn.close.assert_called_once()
    query = cursor.execute.call_args.args[0]
    for required in [
        "rolsuper",
        "rolcreaterole",
        "rolcreatedb",
        "rolbypassrls",
        "rolreplication",
        "has_any_column_privilege",
        "n.nspname NOT IN ('pg_catalog', 'information_schema')",
        "has_table_privilege",
        "INSERT,UPDATE,DELETE,TRUNCATE",
        "has_schema_privilege",
        "'CREATE'",
    ]:
        assert required in query
    assert "private-test" not in capsys.readouterr().err


def test_postgres_privilege_check_failure(monkeypatch, capsys):
    driver = MagicMock()
    conn = driver.connect.return_value
    conn.cursor.return_value.__enter__.return_value.execute.side_effect = RuntimeError(
        "private-test-dsn private-role"
    )
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    monkeypatch.setenv("PHI_AIRGAP_PG_DSN", "private-test-dsn")
    with pytest.raises(SystemExit):
        get_adapter("postgres").connect({})
    conn.close.assert_called_once()
    assert "private" not in capsys.readouterr().err


@pytest.mark.parametrize("dialect", ["postgres", "databricks"])
@pytest.mark.parametrize(
    "sql",
    [
        "with d as (delete from public.t returning 1) select count(*) as n from d",
        "select count(*) as n into public.zz from public.t",
        "select count(*) as n from public.t for update",
    ],
)
def test_read_only_tree(dialect, sql):
    assert not gate.check(sql, {"green": ["*"]}, dialect_name=dialect).allowed


REVIEW_CASES = {
    "benign": ('select language, count(*) as n from public."user" group by language'),
    "tableless_query_to_xml": (
        "select query_to_xml('select * from public.\"user\" limit 150', true, false, '') as x"
    ),
    "tableless_xml_text": (
        "select cast(query_to_xml('select * from public.\"user\"', true, false, '') as text) as x"
    ),
    "tableless_readfile": (
        "select pg_read_file('/etc/passwd') as f, current_setting('data_directory') as d"
    ),
    "tableless_dblink": ("select dblink_exec('dbname=x', 'delete from t') as r"),
    "tableless_terminate": ("select pg_terminate_backend(pid) as r from pg_stat_activity"),
    "rowcast_crossjoin": (
        'select count(*) as n, u::text as r from public."user" u cross '
        'join public."user" v group by u::text'
    ),
    "rowjson_join": (
        'select to_jsonb(u)::text as r, count(*) as n from public."user" u'
        " join public.prompt_skill p on true group by 1"
    ),
    "rowcast_paged": (
        'select count(*) as n, u::text as r from public."user" u cross '
        "join public.prompt_skill v group by u::text order by 2 limit 150 "
        "offset 150"
    ),
    "pg_stats_mcv": (
        "select s.most_common_vals::text as v, count(*) as n from pg_stats"
        " s cross join public.prompt_skill p group by 1"
    ),
    "scalar_sub_key": (
        'select (select u::text from public."user" u offset 5 limit 1) as '
        "r, count(*) as n from public.prompt_skill group by 1"
    ),
    "cte_delete": (
        "with d as (delete from public.prompt_skill returning 1) select count(*) as n from d"
    ),
    "select_into": ("select count(*) as n into public.zz from public.prompt_skill"),
    "for_update": ("select count(*) as n from public.prompt_skill for update"),
    "show_all": ("show all"),
    "sleep_where": ("select count(*) as n from public.prompt_skill where pg_sleep(100) is null"),
    "green_plus_fn": (
        "select query_to_xml('select * from public.\"user\"', true, false, "
        "'') as x from ops_ro.daily"
    ),
    "email_denied": ('select email, count(*) as n from public."user" group by 1'),
    "setconfig": ("select set_config('default_transaction_read_only','off',false) as s"),
    "explain": ("explain analyze delete from public.prompt_skill"),
    "copy": ('copy (select * from public."user") to stdout'),
    "json_fn": (
        "select jsonb_extract_path_text(profile, 'email') as e, count(*) "
        'as n from public."user" cross join public.prompt_skill group by 1'
    ),
    "lo": ("select lo_get(1) as x"),
    "values_inflate": (
        "select count(*) as n, l.self_level, l.fluency_score, l.total_reps"
        " from public.user_language l cross join (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2,3,4"
    ),
    "union_inflate": (
        "select count(*) as n, l.self_level, l.fluency_score, l.total_reps"
        " from public.user_language l cross join (select 1 as x union all "
        "select 2 union all select 3 union all select 4 union all select 5"
        " union all select 6 union all select 7 union all select 8 union "
        "all select 9 union all select 10 union all select 11 union all "
        "select 12) m group by 2,3,4"
    ),
    "cte_inflate": (
        "with m as (select 1 as x union all select 2 union all select 3 "
        "union all select 4 union all select 5 union all select 6 union "
        "all select 7 union all select 8 union all select 9 union all "
        "select 10 union all select 11 union all select 12) select "
        "count(*) as n, l.self_level, l.fluency_score from "
        "public.user_language l cross join m group by 2,3"
    ),
    "cte_values_inflate": (
        "with m(x) as (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) select "
        "count(*) as n, l.self_level, l.fluency_score from "
        "public.user_language l cross join m group by 2,3"
    ),
    "lateral_inflate": (
        "select count(*) as n, l.self_level, l.fluency_score from "
        "public.user_language l cross join lateral (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2,3"
    ),
    "genseries_inflate": (
        "select count(*) as n, l.self_level from public.user_language l "
        "cross join generate_series(1,12) g group by 2"
    ),
    "attr_quote_literal": (
        'select count(*) as n, t.quote_literal as r from public."user" t '
        "cross join (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2"
    ),
    "attr_concat": (
        'select count(*) as n, t.concat as r from public."user" t cross '
        "join (values (1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) "
        "as m(x) group by 2"
    ),
    "attr_quote_nullable_noinflate": (
        'select count(*) as n, t.quote_nullable as r from public."user" t group by 2'
    ),
    "star_cast": (
        'select count(*) as n, (t.*)::text as r from public."user" t cross'
        " join (values (1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12))"
        " as m(x) group by 2"
    ),
    "star_cast2": ('select count(*) as n, cast(t.* as text) as r from public."user" t group by 2'),
    "row_ctor": ('select count(*) as n, row(t.*)::text as r from public."user" t group by 2'),
    "uescape_ident": (
        'select count(*) as n, U&"\\0065m\\0061il" as r from public."user" t'
        " cross join (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2"
    ),
    "uescape_ident2": (
        'select count(*) as n, t.U&"\\0065m\\0061il" as r from public."user"'
        " t cross join (values "
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2"
    ),
    "uescape_first": (
        'select count(*) as n, U&"f\\0069rst_n\\0061me" as r from '
        'public."user" cross join (values '
        "(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12)) as m(x) group"
        " by 2"
    ),
    "nested_comment": ('select count(*) as n /* /* */ , email as r /* */ */ from public."user"'),
    "subq_from_wholerow": (
        'select count(*) as n, s.r from (select u::text as r from public."user" u) s group by 2'
    ),
    "subq_from_star": (
        'select count(*) as n, s.language from (select * from public."user") s group by 2'
    ),
    "subq_alias_launder": (
        'select count(*) as n, s.e from (select email as e from public."user") s group by 2'
    ),
    "array_ctor": (
        'select count(*) as n, array(select language from public."user") '
        "as a from public.prompt_skill"
    ),
    "string_agg": ("select count(*) as n, string_agg(language, ',') as a from public.\"user\""),
    "array_agg": ('select count(*) as n, array_agg(language) as a from public."user"'),
    "json_agg": ('select count(*) as n, json_agg(language) as a from public."user"'),
    "min_text": ('select count(*) as n, min(language) as a, max(language) as b from public."user"'),
    "max_expr_ident": (
        "select count(*) as n, max(cast(total_reps as text) || self_level)"
        " as a from public.user_language"
    ),
    "ts_second": (
        "select date_trunc('second', created_at) as t, count(*) as n from "
        'public."user" group by 1'
    ),
    "ts_epoch": (
        'select extract(epoch from created_at) as t, count(*) as n from public."user" group by 1'
    ),
    "ts_cast": (
        'select cast(created_at as text) as t, count(*) as n from public."user" group by 1'
    ),
    "ts_month_ok": (
        "select date_trunc('month', created_at) as t, count(*) as n from public.\"user\" group by 1"
    ),
    "ts_month_plus": (
        "select date_trunc('month', created_at) as t, created_at - "
        "date_trunc('month', created_at) as d, count(*) as n from "
        'public."user" group by 1, 2'
    ),
    "filter_probe": (
        "select count(*) filter (where total_reps = 5) as n from public.user_language"
    ),
    "tuple_cast": (
        "select count(*) as n, (l.self_level, l.fluency_score, "
        "l.total_reps)::text as r from public.user_language l cross join "
        "(values (1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12))"
    ),
}


@pytest.mark.parametrize("name,sql", REVIEW_CASES.items(), ids=REVIEW_CASES.keys())
def test_round3_review(name, sql):
    policy = {
        "green": ["ops_ro.*"],
        "deny_columns": ["email", "created_at"],
        "count_columns": ["n"],
    }
    verdict = gate.check(sql, policy, INDEX, dialect_name="postgres")
    assert verdict.allowed == (name in {"benign", "ts_month_ok"}), verdict.reasons


@pytest.mark.parametrize("dialect", ["postgres", "databricks"])
def test_unknown_columns(dialect):
    for expression in ["t.quote_literal", "t.concat", "t.quote_nullable", "missing"]:
        v = gate.check(
            f'select {expression}, count(*) as n from public."user" t group by 1',
            {},
            INDEX,
            dialect_name=dialect,
        )
        assert not v.allowed
        assert any("metadata" in reason for reason in v.reasons)


@pytest.mark.parametrize("operator", ["union", "union all", "intersect", "except"])
def test_postgres_set_operations(operator):
    sql = (
        f"select count(*) as n from ops_ro.daily {operator} select count(*) as n from ops_ro.daily"
    )
    assert not gate.check(sql, {"green": ["ops_ro.*"]}, INDEX, dialect_name="postgres").allowed


def test_r14_reason_does_not_expose_counts():
    index = {
        "public.t": {
            "row_count": 1234,
            "columns": {"opaque": {"type": "text", "distinct_count": 1230}},
        }
    }
    verdict = gate.check(
        "select opaque, count(*) as n from public.t group by opaque",
        {},
        index,
        dialect_name="postgres",
    )
    assert not verdict.allowed
    assert any("person key" in reason for reason in verdict.reasons)
    assert "1234" not in str(verdict.reasons) and "1230" not in str(verdict.reasons)


@pytest.mark.parametrize(
    "sql",
    [
        'select t.language, count(*) as n from public."user" t(language) group by 1',
        'select count(t.*) as n from public."user" t',
        'select t.language, count(*) as n from other."user" t group by 1',
    ],
)
def test_postgres_metadata_identity(sql):
    assert not gate.check(sql, {}, INDEX, dialect_name="postgres").allowed


def test_cached_column_is_resolved_per_relation():
    index = {**INDEX, "public.other": {"columns": {"quote_nullable": {"type": "text"}}}}
    sql = (
        'select t.quote_nullable, count(*) as n from public."user" t '
        "cross join public.other o group by 1"
    )
    verdict = gate.check(sql, {}, index, dialect_name="databricks")
    assert not verdict.allowed
    assert any("metadata" in reason for reason in verdict.reasons)


ZERO_COUNT_CASES = [
    "select count(NULL) as n, self_level, fluency_score + 0 as f, total_reps + 0 as t "
    "from public.user_language group by 2, 3, 4",
    "select count(*) filter (where 1 = 0) as n, self_level from public.user_language group by 2",
    "select sum(case when 1 = 0 then 1 else 0 end) as n, self_level "
    "from public.user_language group by 2",
    "select count(cast(null as int)) as n, self_level from public.user_language group by 2",
    "select count(distinct self_level) as n, total_reps from public.user_language group by 2",
]


@pytest.mark.parametrize("sql", ZERO_COUNT_CASES)
def test_round4_forced_zero_counts_denied(sql):
    assert not gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres").allowed


def test_round4_r14_sees_columns_inside_group_expressions():
    index = {
        "public.user_language": {
            "row_count": 1000,
            "columns": {
                "self_level": {"type": "text", "distinct_count": 5},
                "fluency_score": {"type": "numeric", "distinct_count": 990},
            },
        }
    }
    sql = "select count(*) as n, fluency_score + 0 as f from public.user_language group by 2"
    v = gate.check(sql, {}, index, dialect_name="postgres")
    assert not v.allowed
    assert any("person key" in r for r in v.reasons)


def test_round4_fetch_first_denied():
    sql = (
        "select self_level, count(*) as n from public.user_language group by 1 "
        "fetch first 1 rows only"
    )
    assert not gate.check(sql, {}, INDEX, dialect_name="postgres").allowed


INDICATOR_CASES = [
    "select count(*) as n, sum(fluency_score * (1 - cast(cast(total_reps - 805 as boolean) "
    "as int))) as s from public.user_language",
    "select count(*) as n, sum(fluency_score * ((total_reps / 805) * (805 / total_reps))) as s "
    "from public.user_language",
    "select count(*) as n, avg(fluency_score * (total_reps / 805)) as s from public.user_language",
    "select self_level, count(*) as n from public.user_language group by 1 "
    "having sum(fluency_score * (total_reps / 805)) > 1",
    "select self_level, count(*) as n from public.user_language group by 1 "
    "order by max(fluency_score + total_reps)",
]


@pytest.mark.parametrize("sql", INDICATOR_CASES)
def test_round5_aggregate_over_expression_denied(sql):
    assert not gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres").allowed


def test_round5_bare_aggregates_still_allowed():
    sql = (
        "select self_level, count(*) as n, count(fluency_score) as nf, avg(fluency_score) as a, "
        "count(total_reps) as nt, sum(cast(total_reps as numeric)) as s "
        "from public.user_language group by 1"
    )
    v = gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres")
    assert v.allowed, v.reasons


WHERE_PAD_CASES = [
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where total_reps in (805, 0)",
    "select count(*) as n, avg(fluency_score) as s from public.user_language "
    "where (total_reps - 805) * cast(cast(cast(fluency_score as int) / 45 as boolean) as int) = 0",
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where coalesce(fluency_score, 0) * (total_reps - 805) = 0",
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where total_reps = 805 or total_reps = 0",
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where fluency_score is null or total_reps = 805",
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where fluency_score > 80",
    "select count(*) as n, max(fluency_score) as s from public.user_language",
]


@pytest.mark.parametrize("sql", WHERE_PAD_CASES)
def test_round6_where_padding_denied(sql):
    assert not gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres").allowed


def test_round6_simple_and_filter_allowed():
    sql = (
        "select self_level, count(*) as n, count(fluency_score) as nf, avg(fluency_score) as a "
        "from public.user_language where total_reps >= 10 and total_reps > -1 "
        "and self_level <> 'none' group by 1"
    )
    v = gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres")
    assert v.allowed, v.reasons


GROUP_PAD_CASES = [
    "select total_reps in (500, 1115) as k, count(*) as n, count(fluency_score) as nf, "
    "sum(fluency_score) as s from public.user_language group by 1",
    "select case when total_reps = 500 then 1 else 0 end as k, count(*) as n, "
    "count(fluency_score) as nf, sum(fluency_score) as s from public.user_language group by 1",
    "select count(*) as n, count(fluency_score) as nf, sum(fluency_score) as s "
    "from public.user_language group by cast(cast((total_reps - 500) as boolean) as int)",
    "select count(*) as n, sum(fluency_score) as s from public.user_language "
    "where total_reps >= 500 and total_reps <= 1101",
]


@pytest.mark.parametrize("sql", GROUP_PAD_CASES)
def test_round7_group_and_null_padding_denied(sql):
    assert not gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres").allowed


def test_round7_count_col_is_suppressed():
    sql = (
        "select self_level, count(*) as n, count(fluency_score) as nf, avg(fluency_score) as a "
        "from public.user_language group by 1"
    )
    v = gate.check(sql, {"count_columns": ["n"]}, INDEX, dialect_name="postgres")
    assert v.allowed, v.reasons
    assert v.count_idx == {1, 2}
