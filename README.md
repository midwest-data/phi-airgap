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

## Read this first: the deployment shape

The hook is a denylist, not a sandbox. The control that holds is the OS
boundary: **the agent runs under its own OS identity** (separate macOS user,
container, or devcontainer) with **no Keychain entry, no token file and no
network route to the warehouse**; `phi-airgap run` executes only from the
human's session. See [`SECURITY.md`](SECURITY.md#required-deployment-shape)
before the quickstart. Without that shape this is harm reduction against
careless egress, nothing more.

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

`PHI_AIRGAP_CONFIG` / `PHI_AIRGAP_POLICY` may point elsewhere *under*
`~/.phi-airgap/` (or anywhere with `PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1`, which
the selftest sets). Without either, the CLI falls back to the packaged examples
(and `doctor` complains, because an example policy is not a reviewed one).

---

## Quickstart

The agent's loop, once the hook is registered (see below):

```bash
# 0. (human, once) build the cache; --stats adds row/distinct counts so the gate
#    can flag person keys the policy missed (rule R14).
phi-airgap refresh --stats

# 1. Column names, types, descriptions — from a local cache, no network.
phi-airgap schema '*visit*'

# 2. The agent writes SQL to .phi-airgap/q.sql, then confirms it will pass the gate.
#    No network, no credential, no rows.
phi-airgap check .phi-airgap/q.sql

# 3. Only the human runs this. It gates, executes, scrubs, and writes:
#      .phi-airgap/out/q.csv   (scrubbed result)
#      .phi-airgap/out/q.json  (ALLOW/DENY verdict + reasons)
#      .phi-airgap/out/history/<ts>-<sha8>.{sql,json}  (immutable copy)
phi-airgap run .phi-airgap/q.sql --purpose "tie out July ED volumes"
```

The gate's shape: **`group by` the dimensions you care about, project
`count(*) as n` plus your aggregates, and read the number.** A row peek is
denied; an aggregate with a count is allowed. A row whose count is below *k*
is blanked whole (keys included), dates are allowed only at month/quarter/year
precision, and `LIMIT`/`HAVING` below *k*, `ROLLUP`, targeted predicates
inside aggregates, aggregates nested in subqueries and mismatched `UNION`
branches are denied as existence probes. Aggregate once, in the outer SELECT.

```sql
-- DENIED: a row peek
select * from raw.vendor.fact_visit limit 10

-- ALLOWED: an aggregate with a count for k-anonymity to act on
select entity_name, count(*) as n, avg(wait_minutes) as avg_wait
from analytics.core.encounter_fact
group by entity_name
```

`pq` is a packaged short alias for `phi-airgap`; the hook treats both the same
(see "Setting up a working directory for Claude" below).
Other commands: `phi-airgap scrub <file>` (run the scrubber over anything before it
lands in a PR), `phi-airgap dbt run/test` (Keychain token injected, stdout scrubbed,
`show`/`run-operation` blocked), `phi-airgap doctor` / `phi-airgap selftest` (verify the
phi-airgap is intact), `phi-airgap log` (the audit trail).

### Registering the Claude Code hook

See [`hooks/claude-code/README.md`](hooks/claude-code/README.md) for the
`settings.json` `PreToolUse` block and the `CLAUDE.md` protocol template.

---

## Setting up a working directory for Claude

Use the `pq` prefix for every broker-managed command in a workspace: `pq run`,
`pq dbt run`, `pq check`, `pq schema`. It is the same CLI as `phi-airgap`.

```bash
# once per machine (human)
uv tool install --python 3.12 'phi-airgap[databricks,ner]'
pq init                                   # ~/.phi-airgap/{config,policy}.yml, ~/.claude/hooks/, settings.json
$EDITOR ~/.phi-airgap/config.yml          # host, http_path, network_catalogs
$EDITOR ~/.phi-airgap/policy.yml          # your catalogs; every person key into deny_columns
security add-generic-password -a "$USER" -s phi-airgap-databricks-pat -w

# once per working directory (human), from the repo root
mkdir -p .phi-airgap                      # the workspace dir: q.sql, out/, meta/, log.jsonl
printf '.phi-airgap/out/\n.phi-airgap/meta/\n' >> .gitignore   # keep log.jsonl in git if you want the audit there
pq refresh --stats                        # column cache + row/distinct counts (activates rule R14)
pq doctor                                 # hook current, fails closed, no bypass, chains intact
```

The workspace is whichever ancestor of the current directory holds a
`.phi-airgap/` dir (git worktrees get their own), else `default_root` in
config, else the cwd. Everything the agent reads lives under it:
`.phi-airgap/q.sql` (its SQL), `.phi-airgap/out/q.{csv,json}` (scrubbed result
and verdict), `.phi-airgap/meta/columns.json` (schema cache),
`.phi-airgap/log.jsonl` (audit, mirrored under `~/.phi-airgap/audit/`).

Then paste the protocol block from
[`hooks/claude-code/README.md`](hooks/claude-code/README.md) into the
workspace `CLAUDE.md`. The agent's loop becomes:

```bash
pq schema '*visit*'                       # agent: column names, no network
pq check .phi-airgap/q.sql                # agent: will it pass the gate?
pq run .phi-airgap/q.sql --purpose "..."  # HUMAN, typed as `! pq run ...` at the Claude prompt
pq dbt run --select fct_orders            # agent: token injected, stdout scrubbed, GREEN targets refused
pq scrub some_file.md                     # agent: before anything lands in a PR
```

`pq run`, `pq refresh` (without `--offline`), `pq adopt` and `pq uninstall` are
the human's; the hook denies them to the agent under either name. To scope the
hook to one project instead of the whole account, put the `PreToolUse` block
from the hook README in `<repo>/.claude/settings.json` rather than
`~/.claude/settings.json`; the hook still reads `~/.phi-airgap/config.yml`.

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
  the policy the way you would review an ACL, and enumerate every person key
  into `deny_columns`.
- **The hook is a denylist.** It fails closed and inspects scripts and
  interpreter payloads, but uninspected runtimes exist. The deployment shape
  above is the control.

License: [Apache-2.0](LICENSE).
