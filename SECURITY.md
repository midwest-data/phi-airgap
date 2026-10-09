# Security model

## phi-airgap reduces disclosure risk; it does not create HIPAA compliance

This tool exists for one situation: an LLM coding agent needs to do real work
against a warehouse that holds regulated or otherwise sensitive data, and you
want to keep that data out of the model. It lowers the probability and the blast
radius of an accidental disclosure. **It does not make anything compliant.**

If no Business Associate Agreement covers your model provider, there is no lawful
path for PHI to reach that model, and no combination of gate, scrubber and hook
changes that. Deploy this as a harm-reduction control during an interim period,
not as a substitute for the legal and architectural work of getting a BAA'd
inference path. The k≥11 suppression plus identifier stripping *approximates*
HIPAA Safe Harbor; it is **not** an expert determination and not a
certification.

## Required deployment shape

The hook is a denylist against *direct invocation*. It is not a sandbox, and
uninspected runtimes exist. The boundary that actually holds is the operating
system's, so the tool assumes this shape and is not safe without it:

- **The agent runs under its own OS identity** — a separate macOS user, a
  container, or a devcontainer. That identity has **no Keychain entry** for the
  warehouse, **no `.databrickscfg` / `.env` / token file**, and **no network
  route to the warehouse host** (firewall, VPN group, or egress proxy).
- **`phi-airgap run` executes only from the human's session.** The human's
  identity holds the credential; the agent's does not. The hook blocking
  `phi-airgap run` is a guardrail against a careless prompt, not the control.
- The audit mirror under `~/.phi-airgap/audit/` and the hook config live in the
  agent's home, protected by the hook; the workspace log is a convenience copy.

If the agent and the human share one OS identity, any script the agent writes
and runs can read the Keychain and call the warehouse, and no hook rule will
reliably stop it. In that shape this tool is harm reduction against careless
egress only. Say so in your risk register.

## Threat model

**What phi-airgap defends against:** an agent (or a careless prompt) that would pull
row-grain data into the transcript — by querying directly, peeking at rows,
reading a raw extract off disk, or lifting a warehouse credential to do any of
the above.

**Trust boundary:** the agent is **untrusted for data egress**. It may write
SQL, read schema, and read *aggregate, scrubbed* results. It may not execute
queries, read credentials, or read raw extracts. A human runs `phi-airgap run`.

**The three layers, and how each can fail:**

- **The gate** is deterministic and fails closed: an unclassified relation is
  RED, an unparseable statement is denied. Its blind spot is `policy.yml` — a
  GREEN carve-out you scoped too broadly is a hole *you* opened. Review the
  policy like an ACL. The gate also trusts sqlglot's parse; a dialect mismatch
  that mis-parses a statement is a risk, which is why `sql_dialect` must match
  your warehouse.
- **The scrubber** has a deterministic floor (regex for SSN/phone/email/MRN/
  tokens) that cannot miss the shapes it knows, and a statistical ceiling
  (Presidio NER) that **has false negatives by construction**. Presidio scored
  `ssn 123-45-6789` at zero in testing. A clean NER pass is not proof of <!-- phi-airgap: allow -->
  anything. When NER *fires*, the gate already leaked — fix the policy.
- **The hook** enforces the human-runs-the-query rule at the harness level. It
  **fails closed**: malformed input or a crash exits 2 and the harness blocks
  the tool (`hook_fail_open: true` in config restores the old fail-open
  behaviour, on purpose). It inspects interpreter payloads (python, node, ruby,
  perl, php, R), script files handed to a shell, and heredoc bodies for a
  warehouse driver, an HTTP/socket library, Keychain/keyring access,
  `subprocess`, the phi-airgap internals, or the warehouse host — a denylist,
  not a sandbox. `phi-airgap doctor` checks that it is installed, registered,
  current, denies when invoked, and fails closed on garbage.
- **The bypass** is the file `~/.phi-airgap/BYPASS`. The human creates it
  deliberately; the hook denies the agent creating it, and `doctor` reports it.
  The old `PHI_AIRGAP_BYPASS` env var is ignored — an env var can be set from
  an agent-writable settings file.
- **The control plane.** The policy is the ACL. The hook denies Bash writers
  (`sed -i`, `tee`, `cp`, `mv`, `rm`, `>`, `truncate`, `chmod`, `touch`,
  `mkdir`, editors) and the Write/Edit tools on the policy/config files, the
  hook itself, every `.claude/settings*.json` (including `settings.local.json`,
  which can set `env` and `disableAllHooks`), the audit log, its home mirror,
  the query history and the bypass file. `PHI_AIRGAP_CONFIG` / `PHI_AIRGAP_POLICY`
  are honoured only under `~/.phi-airgap/` (or with
  `PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1`, which the selftest sets).
- **The audit log** is hash-chained (each line carries `sha256` of the previous
  line) and mirrored to `~/.phi-airgap/audit/<workspace-hash>.jsonl` (mode
  0600). `phi-airgap run` reads its policy-hash baseline from the mirror and
  prints `*** POLICY CHANGED since last run ***` when `sha256(policy)` or
  `sha256(config)` differs. `doctor` verifies both chains and that the two
  tails agree. A write routed through an interpreter is what this catches.
  Every run also leaves an immutable `out/history/<ts>-<sha8>.{sql,json}` pair.
- **GREEN cannot be minted.** GREEN patterns must be fully qualified to schemas
  the agent cannot write; anything in a `dev_*` schema or a `*_dev` catalog is
  degraded to AMBER by the gate regardless, and `phi-airgap dbt run/build/
  seed/snapshot` refuses a model whose target relation classifies GREEN.

## Before use — checklist

- Deploy in the shape above. Everything else assumes it.
- Enumerate **every re-identifying key** in your warehouse into `deny_columns`
  (`policy.yml`): patient/person/member/subscriber/account keys, source-system
  surrogate ids, natural keys. Grouping by one enumerates individuals, and
  k-anonymity only blanks the row — it cannot know a column is a person key.
  Then run `phi-airgap refresh --stats` (human, warehouse access; one
  `count(*)`/`count(distinct)` per relation, only counts come back) so the
  cache carries `row_count` / `distinct_count` and rule R14 flags any group
  key whose distinct count is at least half the row count — the person keys
  you missed. Without `--stats` R14 is inactive.
- Run `phi-airgap refresh` so `min`/`max` can be typed and `*` screened; with
  no cache, `min`/`max` over sensitive data is denied outright.
- Read every `phi-airgap run` verdict. The human runs the query; the human is
  the last control. `--purpose` records why.

## Known residuals

Shapes the layers do not close. Each is a policy or review decision, not a bug
we intend to fix by adding a rule:

- **Differencing across queries.** Two aggregates that differ by one member
  reveal that member. k-anonymity per query does not defend against this;
  review the audit log (`phi-airgap log`, `out/history/`) for query sequences
  over the same grouping. R10–R12 and R15 close the single-query versions
  (existence probes, ROLLUP marginals, UNION totals, subquery totals and
  targeted counts), not the multi-query one.
- **Column names the example denylist does not know.** The shipped
  `deny_columns` covers generic and Epic/Caboodle-style names (`pat_id`,
  `pat_mrn_id`, `csn_id`, `patientkey`, `last_nm`, `har_id`, ...). An
  identifier under a house name it does not match is allowed as a group key
  and `having count(*) >= 11` then lists it. The denylist is yours to complete;
  `refresh --stats` + R14 is the safety net for what you miss.
- **Computed ages and derived dates.** Birth/death columns never get the
  month/year truncation exemption and no allow pattern can launder a
  `birth_*`/`age_*` name, but a reviewed precomputed `*_year` column can still
  yield an age over 89 by subtraction in the reader's head. Bucket ages before
  they reach the mart.
- **Interpreter writes to the control plane.** Bash writers on protected paths
  are denied, and an interpreter payload that names `.phi-airgap/`, `.claude/`,
  the hook or `BYPASS` is denied; a payload that reaches those paths without
  naming them (built at runtime) is not. The audit mirror and the policy-hash
  banner are the detection; the deployment shape is the prevention.
- **k counts rows, not persons.** A patient with twelve encounters is one
  person and passes k=11 on their own. Aggregate at the grain you mean.
- **The human must read the verdict.** `phi-airgap run` prints ALLOW/DENY,
  suppression and day-precision-date warnings; nothing stops a human from
  running a query they should have questioned.
- **Non-Databricks adapters have no hook coverage** beyond the generic client
  and library denylist. A warehouse reachable through an uninspected runtime
  is reachable. The deployment shape is the control.
- **Uninspected runtimes.** The hook reads python/node/ruby/perl/php/R payloads
  and shell scripts. Compiled binaries, `make`, `cargo run`, notebooks and
  anything not in that list are not inspected.
- **dbt models and macros.** `phi-airgap dbt run` scrubs stdout, but a model or
  macro can `log(run_query(...))` rows into that stdout, and only the scrubber
  (regex floor + NER alarm) stands in the way. Review macros like SQL.
- **Local extracts.** `.parquet` and `.duckdb` reads are denied; `.csv` /
  `.xlsx` files are not, because the scrubbed output is itself a `.csv`. Do not
  leave raw extracts in the workspace.
- **Interpreter writes to the control plane** — see above; the policy-hash
  banner is the detection, not a prevention.
- **The git PHI screen is local.** `pq git install` hooks stop a commit or push
  from this clone; a fresh clone without the hooks, or a human typing
  `--no-verify`, is not stopped (the agent is — the harness hook denies it).
  A server-side check would close that; it is not shipped. Image-only PDFs and
  scanned documents are not OCR'd; legacy `.doc`/`.xls` block rather than scan;
  names are advisory (spaCy misses and over-fires); and an allow marker is a
  trust decision — review `phi-airgap: allow` lines and `.phi-airgap-ignore`
  globs in PRs as you would a policy change.

**Out of scope:** phi-airgap does not defend against a malicious operator, a
compromised warehouse, side channels in aggregate statistics beyond the k-anon
threshold, or a model provider that violates its own retention terms. It does
not encrypt anything or manage access to the warehouse itself.

## What a BAA gives you that this cannot

This tool exists to let an agent work *near* PHI while a Business Associate
Agreement with the model provider is being acquired. It never replaces one:

- **A contract.** A BAA binds the provider to HIPAA's Security and Privacy
  Rules, permitted uses and disclosures, and subcontractor flow-down. Nothing
  here binds anyone.
- **Breach notification.** A BAA obliges the provider to report a breach to
  you within a defined window so you can meet your own notification duties.
  Without it, a disclosure in a transcript is discovered by you or not at all.
- **Vendor-side safeguards.** Retention limits, no training on your data,
  access controls and audit on the provider's side, with the right to verify.
  This tool controls only what leaves your machine.
- **Liability and enforcement.** A BAA allocates liability and makes the
  provider directly accountable to HHS. Without it, an authorized disclosure
  of PHI to the provider does not exist — the best case here is that nothing
  was disclosed, which is what the layers try to make true.

## Responsible disclosure

If you find a way to get row-grain data past the gate or the scrubber — a query
shape the gate allows that it should not, a scrubber false negative on a
deterministic shape, or a hook bypass — please report it privately rather than
opening a public issue. Open a [GitHub security
advisory](https://docs.github.com/en/code-security/security-advisories) on this
repository (**Security → Report a vulnerability**), or contact the maintainer
listed in the repository metadata.

When reporting, describe the *class* of the problem and a minimal reproducing
query or command. Please do not include real PHI in a report.
