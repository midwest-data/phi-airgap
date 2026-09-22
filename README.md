# phi-airgap

**A PHI-airgap query broker for LLM coding agents.**

An AI coding agent that helps you build against a sensitive SQL warehouse has a
data-plane problem: the moment a query result reaches the model, that data is in
the transcript, the provider's logs, and — for regulated data with no BAA in
place — an unauthorized disclosure. `phi-airgap` lets the agent do real warehouse
work (write SQL, review PRs, author dbt models, tie out metrics) **without any
row-grain data reaching the model.**

The agent is treated as untrusted for data egress. It writes SQL; a human runs
it; the agent reads a scrubbed, aggregate-only result. Three independent layers
enforce that:

1. **The gate** (`gate.py`) — a deterministic, structural SQL policy. It parses
   the statement with [sqlglot](https://github.com/tobymao/sqlglot), classifies
   every relation RED / AMBER / GREEN, and denies anything that could emit
   row-grain data: row peeks, `SELECT DISTINCT`, window-function "aggregates",
   aggregates with no count column for k-anonymity to bite on, any reference to
   an identifier column anywhere in the statement, and path/table-function reads
   that dodge classification. **Unknown relation ⇒ RED. Unparseable ⇒ denied.**
2. **The scrubber** (`scrub.py`) — the last line before a result is written.
   A deterministic regex pass (SSN/phone/email/MRN/tokens), k-anonymity
   suppression (cells with a count below *k* become `<11`), and a Presidio NER
   pass that is an **alarm, not a save**.
3. **The hook** (`hooks/claude-code/`) — a Claude Code `PreToolUse` hook that
   enforces "the agent never runs the query, never reads a credential, never
   opens a raw extract." Instructions are the belt; the hook is the braces.

The engine is warehouse-agnostic behind a small DBAPI adapter seam. A Databricks
reference adapter ships; adding another warehouse is ~30 lines.

---

## Install

```bash
# core: the gate + hook only (fast, no heavy deps)
pip install phi-airgap

# with the NER alarm and the Databricks adapter
pip install "phi-airgap[ner,databricks]"
```

**Python is pinned to `>=3.12,<3.13`.** The `[ner]` extra pulls spaCy and the
`en_core_web_lg` model (~500 MB), whose wheels do not resolve on 3.13+. The core
gate and hook have no such constraint, but the project is pinned to one
supported interpreter for simplicity. If you only need the gate and hook, you
still need 3.12 to install from this pyproject.

Then seed the config, policy and the Claude Code hook in one step, and edit
the two YAML files (they are the ACL):

```bash
phi-airgap init          # ~/.phi-airgap/{config,policy}.yml + ~/.claude/hooks/ + settings.json
$EDITOR ~/.phi-airgap/config.yml ~/.phi-airgap/policy.yml
phi-airgap doctor        # hook installed, current, and actually denying
```

`PHI_AIRGAP_CONFIG` / `PHI_AIRGAP_POLICY` override the `~/.phi-airgap/` paths.
Without either, the CLI falls back to the packaged examples (and `doctor`
complains, because an example policy is not a reviewed one).

---

## Quickstart

The agent's loop, once the hook is registered (see below):

```bash
# 1. Column names, types, descriptions — from a local cache, no network.
phi-airgap schema '*visit*'

# 2. The agent writes SQL to .phi-airgap/q.sql, then confirms it will pass the gate.
#    No network, no credential, no rows.
phi-airgap check .phi-airgap/q.sql

# 3. Only the human runs this. It gates, executes, scrubs, and writes:
#      .phi-airgap/out/q.csv   (scrubbed result)
#      .phi-airgap/out/q.json  (ALLOW/DENY verdict + reasons)
phi-airgap run .phi-airgap/q.sql
```

The gate's shape: **`group by` the dimensions you care about, project
`count(*) as n` plus your aggregates, and read the number.** A row peek is
denied; an aggregate with a count is allowed.

```sql
-- DENIED: a row peek
select * from raw.vendor.fact_visit limit 10

-- ALLOWED: an aggregate with a count for k-anonymity to act on
select entity_name, count(*) as n, avg(wait_minutes) as avg_wait
from analytics.core.encounter_fact
group by entity_name
```

Other commands: `phi-airgap scrub <file>` (run the scrubber over anything before it
lands in a PR), `phi-airgap dbt run/test` (Keychain token injected, stdout scrubbed,
`show`/`run-operation` blocked), `phi-airgap doctor` / `phi-airgap selftest` (verify the
phi-airgap is intact), `phi-airgap log` (the audit trail).

### Registering the Claude Code hook

See [`hooks/claude-code/README.md`](hooks/claude-code/README.md) for the
`settings.json` `PreToolUse` block and the `CLAUDE.md` protocol template.

---

## The warehouse seam

`config.adapter` selects a DBAPI adapter; `config.sql_dialect` sets the sqlglot
dialect the gate parses in. Only `databricks` ships. Any PEP 249 driver
satisfies the contract (`connect(cfg)` → a connection with
`cursor()`/`execute`/`description`/`fetchmany`), so a Postgres or Snowflake
adapter is roughly:

```python
# src/phi_airgap/adapters/postgres.py
import sys
from . import register

def connect(cfg):
    import psycopg
    return psycopg.connect(cfg["host"])

register("postgres", sys.modules[__name__])
```

Then set `adapter: postgres` and `sql_dialect: postgres`. See
[`src/phi_airgap/adapters/__init__.py`](src/phi_airgap/adapters/__init__.py) for the
full contract.

---

## Honest limits

Read [`SECURITY.md`](SECURITY.md) before relying on this for anything. The short
version:

- **`phi-airgap` reduces disclosure risk. It does not create HIPAA compliance.** If
  no BAA covers your model provider, there is no lawful path for PHI no matter
  what controls exist here. This tool lowers the odds and the blast radius of an
  accidental disclosure; it does not authorize one.
- **The k≥11 suppression plus identifier stripping only *approximates* Safe
  Harbor.** It is not an expert determination, and it is not a certification.
- **Presidio is an alarm, not a save.** The NER pass has false negatives *by
  construction* — in testing it scored `ssn 123-45-6789` at zero. A clean NER
  pass is never proof that a result is PHI-free. When it *does* fire, that means
  the gate leaked and the policy needs fixing — treat it as a bug, not a catch.
- **The gate is only as good as `policy.yml`.** An unclassified relation fails
  closed to RED, but a mis-scoped GREEN carve-out is a hole you opened. Review
  the policy the way you would review an ACL.

License: [Apache-2.0](LICENSE).
