# Claude Code enforcement hook

`pretool-phi-airgap.py` is a Claude Code `PreToolUse` hook, shipped inside the
package at `phi_airgap/data/`. It denies the Bash, Read, Grep, Write and Edit
tool calls that would put row-grain data into the agent's context — executing a
query, reading a credential, opening a raw extract — and the writes that would
rewrite the control plane (the policy/config files, the hook itself, every
`.claude/settings*.json`, the audit log and its mirror, the query history, the
bypass file). It is the **braces**; the `CLAUDE.md` protocol block below is the
**belt**.

**It is a denylist against direct invocation, not a sandbox.** Uninspected
runtimes exist. The control that holds is the deployment shape in
[`SECURITY.md`](../../SECURITY.md#required-deployment-shape): the agent's OS
identity holds no credential and has no route to the warehouse.

Leading wrappers are peeled before the command-position token is judged, so
`uv run phi-airgap run`, `env python3 -c …`, `timeout 30 databricks …`,
`bash -c "…"` and `python3 -m phi_airgap.cli run` are all denied like their
bare forms. Script files handed to a shell (`bash s.sh`, `./s.sh`, `source
s.sh`) and heredoc bodies are read and judged as shell code. Interpreter
payloads (python, node, ruby, perl, php, R — `-c`/`-e` text, heredocs, and the
script files named) are denied if they mention a warehouse driver, an
HTTP/socket library, Keychain/keyring access, `subprocess`, the phi-airgap
internals, or the configured warehouse host.

The hook is standalone and dependency-free: it runs on the system Python with no
third-party packages. It reads a few scalars from your config (see below), and
it **fails closed** — malformed input or a crash exits 2 and the harness
blocks the tool. Set `hook_fail_open: true` in config to restore the old
fail-open behaviour on purpose.

## Install

`phi-airgap init` does all of the following. By hand:

1. Copy the hook where your harness can run it, e.g.:

   ```bash
   mkdir -p ~/.claude/hooks
   cp "$(python3 -c 'import phi_airgap.util as u; print(u.DATA)')"/pretool-phi-airgap.py ~/.claude/hooks/
   chmod +x ~/.claude/hooks/pretool-phi-airgap.py
   ```

2. Give it a config to read: `~/.phi-airgap/config.yml` (`$PHI_AIRGAP_CONFIG`
   is honoured only if it points under `~/.phi-airgap/`, or with
   `PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1`). It reads only three flat scalars:

   - `host` — the warehouse host; direct `curl`/`wget`/`nc` to it, and any
     interpreter payload naming it, is blocked.
   - `readable_keychain_service` — the one Keychain service the agent may read
     (for a credential that reaches no sensitive data, e.g. an issue-tracker
     API key). Empty ⇒ every Keychain read is denied.
   - `hook_fail_open` — `false` by default.

   ```bash
   phi-airgap init   # or copy phi_airgap/data/config.example.yml to ~/.phi-airgap/config.yml
   ```

3. Register it in `~/.claude/settings.json` under `PreToolUse`, matching the
   Bash, Read, Grep, Write and Edit tools:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|Read|Write|Edit|MultiEdit|Grep",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/hooks/pretool-phi-airgap.py"
             }
           ]
         }
       ]
     }
   }
   ```

4. Verify: `phi-airgap doctor` checks the hook is present, byte-identical to
   the packaged version, registered, actually denies `phi-airgap run` when
   invoked, fails closed on malformed input, and that no bypass file exists;
   `phi-airgap selftest` red-teams the packaged hook.

## Bypass

The file `~/.phi-airgap/BYPASS` disables the hook while it exists. The human
creates it deliberately (`touch ~/.phi-airgap/BYPASS`) and removes it after;
the hook denies the agent creating it, and `phi-airgap doctor` reports it as a
failure. The old `PHI_AIRGAP_BYPASS` env var is ignored: an env var can be set
from `.claude/settings.local.json`, which is why that file is protected too.

## The `CLAUDE.md` protocol block (template)

Add a block like this to your workspace `CLAUDE.md` so the agent knows the
protocol. `pq` is the packaged short alias for `phi-airgap`; the hook treats
both the same. Adjust catalog names and the tone to your project. Generic
wording:

```markdown
## PHI airgap — how data access works here

This workspace touches a warehouse holding sensitive data, and there is no BAA
covering this model provider. So no row-grain data may reach the model. Data
access goes through the `pq` broker, and `~/.claude/hooks/pretool-phi-airgap.py`
enforces it regardless of what this file says. **This does not make anything
compliant.**

| Need | Do this |
|---|---|
| Column names, types, descriptions | `pq schema <pattern>` — local cache, no network. **Not a query.** |
| A number from the warehouse | Write SQL to `.phi-airgap/q.sql`, confirm it passes with `pq check .phi-airgap/q.sql`, then ask the user to run `! pq run .phi-airgap/q.sql` |
| Will my SQL pass the gate? | `pq check <f.sql>` — the gate only. No network, no credential, no rows. |
| The result | Read `.phi-airgap/out/q.csv` (scrubbed) and `.phi-airgap/out/q.json` (verdict) |
| A dbt build | `pq dbt run --select <model>` / `pq dbt test ...` |
| Scrub anything before a PR | `pq scrub <file>` |
| Commit / push | Normally. The git hooks screen every commit and push for PHI; a finding means stop and report it. **Never `--no-verify`**, never add a `phi-airgap: allow` marker yourself. |
| Check the airgap is intact | `pq doctor`, `pq selftest`, `pq log` |

The agent **never** executes SQL, reads a credential, or runs `pq run` /
`pq refresh` (without `--offline`) / `pq adopt` / `pq uninstall` /
`pq git uninstall` — those are
the human's. The hook enforces this.

The working shape for any query over sensitive data: **`group by` the dimensions
you care about, project `count(*) as n` plus your aggregates, and read the
number.** A row peek is denied; an aggregate with a count is allowed.
```
