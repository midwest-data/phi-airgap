# Claude Code enforcement hook

`pretool-phi-airgap.py` is a Claude Code `PreToolUse` hook, shipped inside the
package at `phi_airgap/data/`. It denies the Bash, Read, Grep, Write and Edit
tool calls that would put row-grain data into the agent's context — executing a
query, reading a credential, opening a raw extract — and the writes that would
rewrite the control plane (the policy/config files, the hook itself,
`~/.claude/settings.json`). It is the **braces**; the `CLAUDE.md` protocol block
below is the **belt**.

Leading wrappers are peeled before the command-position token is judged, so
`uv run phi-airgap run`, `env python3 -c …`, `timeout 30 databricks …`,
`bash -c "…"` and `python3 -m phi_airgap.cli run` are all denied like their
bare forms.

The hook is standalone and dependency-free: it runs on the system Python with no
third-party packages. It reads a few scalars from your config (see below), and
it **fails open by design** — if it crashes, it exits 0 and allows the tool,
because a broken governance hook must never wedge the agent.

## Install

`phi-airgap init` does all of the following. By hand:

1. Copy the hook where your harness can run it, e.g.:

   ```bash
   mkdir -p ~/.claude/hooks
   cp "$(python3 -c 'import phi_airgap.util as u; print(u.DATA)')"/pretool-phi-airgap.py ~/.claude/hooks/
   chmod +x ~/.claude/hooks/pretool-phi-airgap.py
   ```

2. Give it a config to read. The hook looks at `$PHI_AIRGAP_CONFIG`, else
   `~/.phi-airgap/config.yml`. It reads only three flat scalars:

   - `host` — the warehouse host; direct `curl`/`wget`/`nc` to it is blocked.
   - `readable_keychain_service` — the one Keychain service the agent may read
     (for a credential that reaches no sensitive data, e.g. an issue-tracker
     API key). Empty ⇒ every Keychain read is denied.

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
   the packaged version, registered, and actually denies `phi-airgap run` when
   invoked; `phi-airgap selftest` red-teams the packaged hook.

## Bypass

`PHI_AIRGAP_BYPASS=1` disables the hook for that process. It exists for the human to
use deliberately. If it is set in the agent's environment, there is no hook.

## The `CLAUDE.md` protocol block (template)

Add a block like this to your workspace `CLAUDE.md` so the agent knows the
protocol. Adjust catalog names and the tone to your project. Generic wording:

```markdown
## PHI airgap — how data access works here

This workspace touches a warehouse holding sensitive data, and there is no BAA
covering this model provider. So no row-grain data may reach the model. Data
access goes through `phi-airgap`, and `~/.claude/hooks/pretool-phi-airgap.py` enforces
it regardless of what this file says. **This does not make anything compliant.**

| Need | Do this |
|---|---|
| Column names, types, descriptions | `phi-airgap schema <pattern>` — local cache, no network. **Not a query.** |
| A number from the warehouse | Write SQL to `.phi-airgap/q.sql`, confirm it passes with `phi-airgap check .phi-airgap/q.sql`, then ask the user to run `! phi-airgap run .phi-airgap/q.sql` |
| Will my SQL pass the gate? | `phi-airgap check <f.sql>` — the gate only. No network, no credential, no rows. |
| The result | Read `.phi-airgap/out/q.csv` (scrubbed) and `.phi-airgap/out/q.json` (verdict) |
| A dbt build | `phi-airgap dbt run --select <model>` / `phi-airgap dbt test ...` |
| Scrub anything before a PR | `phi-airgap scrub <file>` |
| Check the phi-airgap is intact | `phi-airgap doctor`, `phi-airgap selftest`, `phi-airgap log` |

The agent **never** executes SQL, reads a credential, or runs `phi-airgap run` /
`phi-airgap refresh` (without `--offline`) / `phi-airgap adopt` / `phi-airgap uninstall` —
those are the human's. The hook enforces this.

The working shape for any query over sensitive data: **`group by` the dimensions
you care about, project `count(*) as n` plus your aggregates, and read the
number.** A row peek is denied; an aggregate with a count is allowed.
```
