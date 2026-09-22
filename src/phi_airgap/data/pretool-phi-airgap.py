#!/usr/bin/env python3
# hook-version: 1.2.0
"""
PreToolUse:Bash|Read|Write|Edit|MultiEdit|Grep Hook: PHI Airgap enforcement (Claude Code).

Blocks the execution and read paths that could put live row-grain data into an
LLM agent's context. Instructions in CLAUDE.md are the belt; this hook is the
braces — it denies the tool call regardless of what the prose says.

This is a HARD GATE — it prints a JSON permissionDecision:deny to block, and
otherwise exits 0 to allow. It FAILS CLOSED: malformed input or a crash exits 2
(the harness blocks the tool) unless config `hook_fail_open: true`.

This hook is a best-effort DENYLIST against direct invocation. It is not a
sandbox: uninspected runtimes exist, and the real boundary is the deployment
shape (SECURITY.md "Required deployment shape") — the agent's OS identity must
hold no warehouse credential and no network route to the warehouse.

Every decision is made per execution segment, on the token in COMMAND position,
after leading wrappers (env, nice, timeout, sudo, uv run, poetry run, xargs, ...)
are stripped and `bash -c "<str>"` / `python -m phi_airgap` are unwrapped.
Script files handed to a shell (`bash s.sh`, `source s.sh`, `./s.sh`) and shell
heredoc bodies are read and judged as shell code too.

Denied on Bash:
- a SQL client (databricks / dbsql / psql / sqlite3 / mysql / snowsql / bq / ...)
- any interpreter invocation (python, uv, node, ruby, perl, php, R, ...) whose
  command text, heredoc body, or script file mentions a warehouse driver, an
  HTTP/socket library, Keychain/keyring access, subprocess, the phi-airgap
  internals, duckdb, a .parquet file, or the configured warehouse host
- dbt show / dbt run-operation (these print result rows), incl. via `phi-airgap dbt`
- reading a credential out of Keychain, EXCEPT the one non-sensitive service
  named by config `readable_keychain_service` (empty by default → all denied)
- curl/wget/nc against the configured warehouse host
  (`pq` is the same CLI under its short alias and is judged identically)
- phi-airgap run / uninstall / adopt, and `phi-airgap refresh` without --offline
- reading a .env / .envrc / .env.<suffix> with a reader command, and redirecting
  into any of them (.env.example / .env.template / .env.sample stay readable)
- writing to the control plane: the policy/config files, this hook, any
  .claude/settings*.json, the audit log (.phi-airgap/log.jsonl, ~/.phi-airgap/audit/),
  the query history (.phi-airgap/out/history/) and ~/.phi-airgap/BYPASS
  (sed -i, tee, cp, mv, rm, >, >>, truncate, chmod, editors). The policy is the
  ACL; the human edits it.

Denied on Read / Grep (path):
- *.parquet, *.duckdb, .phi-airgap/out/*.raw.*, **/.envrc, **/.env(.local|...)

Denied on Write / Edit / MultiEdit (file_path):
- everything in the Read list, plus the control-plane files above

Allow-through:
- everything else, including `phi-airgap schema`, `phi-airgap scrub`, `phi-airgap log`,
  `phi-airgap doctor`, `phi-airgap selftest`, `phi-airgap refresh --offline`,
  `phi-airgap dbt run/test/build`, and all normal git/dbt/gh/file work
- the file ~/.phi-airgap/BYPASS exists (human-created; the hook itself denies
  the agent creating it, and `phi-airgap doctor` reports it)

Config: ~/.phi-airgap/config.yml. $PHI_AIRGAP_CONFIG is honoured only if it points
under ~/.phi-airgap/ or PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1 is set (the selftest sets
it). Only flat scalars are read (no yaml dependency — the hook runs on the
system python). Missing config falls back to safe defaults: no readable
Keychain service, host unset, fail closed.

Verified by tests/test_airgap.py (`phi-airgap selftest`).
"""

import json
import os
import re
import shlex
import sys
import traceback
from pathlib import Path

_HOME_DIR = Path.home() / ".phi-airgap"
_BYPASS_FILE = _HOME_DIR / "BYPASS"

_PROTOCOL = (
    "PHI AIRGAP: live row-grain data must not reach your context. Do not execute "
    "queries. Instead: write the SQL to .phi-airgap/q.sql and ask the user to run "
    "`! phi-airgap run .phi-airgap/q.sql`. Read the scrubbed result at .phi-airgap/out/q.csv "
    "and the ALLOW/DENY verdict at .phi-airgap/out/q.json. For column names use "
    "`phi-airgap schema <pattern>` (local cache, no network)."
)

# --- config (dependency-free flat-scalar reader) -----------------------------


def _env_path(env: str, default: Path) -> Path:
    """$ENV override, honoured only under ~/.phi-airgap/ or with the explicit
    PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1 — otherwise a settings `env` block could
    point the hook at a config the agent wrote."""
    v = os.environ.get(env)
    if not v:
        return default
    p = Path(v).expanduser()
    try:
        under_home = p.resolve().is_relative_to(_HOME_DIR.resolve())
    except (OSError, RuntimeError):
        under_home = False
    if under_home or os.environ.get("PHI_AIRGAP_ALLOW_ENV_OVERRIDE") == "1":
        return p
    return default


_CONFIG = _env_path("PHI_AIRGAP_CONFIG", _HOME_DIR / "config.yml")


def _config_value(key: str, fallback: str) -> str:
    """One scalar out of config.yml, without a yaml dependency.

    The hook runs on the system python with no third-party packages, so a real
    parser is not available here. Only flat `key: value` scalars are read.
    """
    try:
        m = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", _CONFIG.read_text(), re.M)
        if m:
            return re.sub(r"\s+#.*$", "", m.group(1)).strip().strip("'\"")
    except OSError:
        pass
    return fallback


def _readable_service() -> str:
    return _config_value("readable_keychain_service", "")


def _warehouse_host() -> str:
    return _config_value("host", "")


# --- the control plane --------------------------------------------------------
# The policy is the ACL the gate enforces; the hook and settings.json are what
# make it bite. The agent may read them, never rewrite them. The audit log and
# the query history are the record; the agent may read them, never rewrite them.

_PROTECTED_SUFFIXES = (
    "/.phi-airgap/policy.yml",
    "/.phi-airgap/config.yml",
    "/.phi-airgap/log.jsonl",
    "/.phi-airgap/BYPASS",
    "/.claude/hooks/pretool-phi-airgap.py",
    "/.claude/settings.json",
    "/.claude/settings.local.json",
)
# Directories whose every file is protected.
_PROTECTED_DIRS = ("/.phi-airgap/audit/", "/.phi-airgap/out/history/")
# Any settings file of the harness: settings.json, settings.local.json, settings.<x>.json.
_SETTINGS_FILE = re.compile(r"/\.claude/settings[^/]*\.json$")


def _protected_files() -> set[str]:
    home = Path.home()
    files = {
        _CONFIG,
        _env_path("PHI_AIRGAP_POLICY", _HOME_DIR / "policy.yml"),
        home / ".claude" / "hooks" / "pretool-phi-airgap.py",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        _BYPASS_FILE,
        *_HOME_DIR.glob("*.yml"),
    }
    return {str(Path(f).expanduser().resolve()) for f in files}


def _is_protected(token: str) -> bool:
    tok = token.strip("'\"")
    if not tok or "/" not in tok and "." not in tok:
        return False
    try:
        resolved = str(Path(os.path.expanduser(tok)).resolve())
    except (OSError, RuntimeError):
        resolved = tok
    return (
        resolved in _protected_files()
        or resolved.endswith(_PROTECTED_SUFFIXES)
        or any(d in resolved + "/" for d in _PROTECTED_DIRS)
        or bool(_SETTINGS_FILE.search(resolved))
    )


_PROTECTED_REASON = (
    "The policy is the ACL; the human edits it. Writing to the phi-airgap policy/config, "
    "the enforcement hook, .claude/settings*.json, the audit log or the query history is "
    "blocked. Ask the user to make the change."
)

# Command-position executables that overwrite or delete their path arguments.
_WRITERS = {
    "tee", "cp", "mv", "rm", "truncate", "chmod", "chown", "install", "ln", "dd", "rsync",
    "vim", "vi", "nano", "emacs", "code", "open", "shred", "unlink", "touch", "mkdir",
}


def _writes_protected(words: list[str]) -> bool:
    exe = _basename(words[0])
    in_place = exe in {"sed", "perl"} and any(
        w == "--in-place" or re.match(r"^-[a-zA-Z]*i", w) for w in words[1:]
    )
    if (exe in _WRITERS or in_place) and any(_is_protected(w) for w in words[1:]):
        return True
    return any(
        w in (">", ">>") and i + 1 < len(words) and _is_protected(words[i + 1])
        for i, w in enumerate(words)
    )


# --- Bash patterns -----------------------------------------------------------

# Command-position executables that talk to a warehouse or a local database.
_SQL_CLIENTS = {
    "databricks", "dbsql", "databricks-sql", "databricks-sql-cli",
    "psql", "sqlite3", "mysql", "mariadb", "clickhouse-client", "bq", "snowsql", "duckdb",
    "sqlcmd",
}

# Python-ish interpreters, unwrapped for `-m phi_airgap` / `-m dbt`.
_PY_RUNNER_NAMES = {
    "python", "python2", "python3", "python3.11", "python3.12", "python3.13", "python3.14",
    "uv", "uvx", "ipython", "ipython3", "jupyter", "pytest", "poetry", "pipenv",
}
# Every interpreter whose payload is inspected.
_INTERPRETERS = _PY_RUNNER_NAMES | {"node", "deno", "bun", "ruby", "perl", "php", "Rscript", "R"}

# Forbidden payload inside anything an interpreter would execute: a warehouse
# driver, a network client, a credential store, a subprocess escape, or the
# phi-airgap internals (which hold the credential path).
# ponytail: a denylist chasing runtimes; the boundary is the deployment shape.
_PY_FORBIDDEN = re.compile(
    r"\bdatabricks\b"
    r"|\bduckdb\b"
    r"|read_parquet"
    r"|\.parquet\b"
    r"|keychain|keyring|find-generic-password|\bsecurity\b.*-w"
    r"|subprocess|os\.system|os\.popen|os\.exec|child_process|\bexecSync\b|\bspawn\b"
    r"|importlib|__import__|\bexec\s*\(|\beval\s*\("
    r"|phi_airgap\.(?:util|run|adapters|cli)"
    r"|pyodbc|psycopg|snowflake|sqlalchemy|databricks://"
    r"|urllib|requests|http\.client|httpx|aiohttp|socket\b"
    r"|\bfetch\s*\(|\bnet\.connect|Net::HTTP|net/https?\b|LWP::|curl_init"
    # The control plane by path: an interpreter can write what the shell writers cannot.
    r"|\.phi-airgap/|\.claude/|pretool-phi-airgap|settings\.local|\bBYPASS\b",
    re.IGNORECASE,
)

_KEYCHAIN_READ = re.compile(r"\b(?:find|dump)-generic-password\b", re.IGNORECASE)

# dbt subcommands that print result rows.
_DBT_BLOCKED = {"show", "run-operation"}
# phi-airgap subcommands only the human may run. `refresh` is handled separately: it
# hits information_schema by default, but `--offline` reads only a local dbt
# manifest and writes column names, which are not PHI.
_PQ_BLOCKED = {"run", "uninstall", "adopt"}

# Commands that would read a credential file out to stdout or into the env.
_READERS = {
    "cat", "bat", "less", "more", "head", "tail", "grep", "rg", "ag", "awk", "sed",
    "strings", "xxd", "od", "cut", "tr", "sort", "uniq", "wc", "jq", "yq", "tee",
    "dd", "base64", "cp", "mv", "rsync", "scp", "open", "code", "vim", "vi", "nano",
    "emacs", "source", ".", "eval", "export", "printenv", "env", "python", "python3",
    "node", "ruby", "perl", "php", "direnv", "dotenv",
}

# Every env-file path token in a segment, so each can be judged on its own.
# `.env` must sit at a genuine path boundary and any prefix must be real
# directory components (each ending in `/`). Without that, prose like
# "the .env carve-out" parsed as a path token and denied writing about the
# phi-airgap — the same class of false positive the heredoc split exists for.
_ENVFILE_TOKEN = re.compile(
    r"""(?:^|[\s'"=])(/?(?:[\w.~-]+/)*)\.env(?:rc|\.[\w-]+)?\b"""
)

_DOC_SUFFIXES = {".env.example", ".env.template", ".env.sample"}


def _denied_envfile(seg: str) -> bool:
    """True if this segment names a credential env file (not a doc template).

      .envrc, any/path/.envrc          -> denied
      .env, dir/.env, a/b/.env         -> denied
      .env.local, .env.pre-airgap      -> denied
      .env.example/.template/.sample   -> allowed, they are documentation
    """
    for m in _ENVFILE_TOKEN.finditer(seg):
        base = m.group(0)[m.end(1) - m.start(0) :]
        if base in _DOC_SUFFIXES:
            continue
        return True
    return False


# Writing a credential back into a dotfile is as bad as reading one out.
# `\.env(?:rc)?` — NOT `\.envrc?`, which makes the `r` mandatory and so never
# matches a plain `.env`.
_ENVFILE_REDIRECT = re.compile(
    r">>?\s*['\"]?[\w./~-]*\.env(?:rc)?\b(?!\.example|\.template|\.sample)"
)


_HEREDOC = re.compile(r"<<-?\s*[\"']?(\w+)[\"']?\n(.*?)\n\s*\1\b", re.DOTALL)


def _split_heredocs(command: str) -> tuple[str, str]:
    """Separate shell code from heredoc bodies.

    A heredoc body is DATA. Segmenting it as if it were code is what made this
    hook refuse `python3 - <<PY ... PY` scripts that merely mention `.env`. The
    body is still inspected — as an interpreter payload, and as shell code when
    a shell is what reads it (`bash <<EOF`).
    """
    bodies = [m.group(2) for m in _HEREDOC.finditer(command)]
    return _HEREDOC.sub(lambda m: f"<<{m.group(1)}", command), "\n".join(bodies)


_OPERATORS = {"|", "||", ";", "&", "&&", "\n", "(", ")"}


def _segments(command: str) -> list[list[str]]:
    """Split shell code into execution segments as token lists.

    Uses shlex so that a `|` inside a quoted argument stays part of that
    argument. Splitting on raw `|` chopped `grep -E 'a|databricks|b'` into a
    segment beginning with `databricks` and denied it as a SQL-client
    invocation — a whole class of false positive.
    """
    # shlex does not treat backticks as an operator, so `` `databricks sql` ``
    # would stay glued to the previous token. $( ) is handled by
    # punctuation_chars.
    command = command.replace("`", " ; ")
    try:
        # A newline is an operator, not whitespace: with the default lexer,
        # `git status\nphi-airgap run q.sql` was one segment beginning `git`.
        lexer = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:  # unbalanced quotes — fall back to the coarse split
        return [s.split() for s in re.split(r"[;&|\n]+|\$\(|`", command) if s.strip()]
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        tok = tok.replace("\n", "") if "\n" in tok and set(tok) <= set("();<>|&\n") else tok
        if tok in _OPERATORS or tok == "":
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


_SKIP_TOKENS = {
    "sudo", "command", "exec", "time", "nohup", "nice", "xargs", "uvx", "then", "do", "else",
    "!", "{", "(",
}
# `<tool> run <cmd>` wrappers: the real command sits after `run` and its flags.
_RUN_WRAPPERS = {"uv", "poetry", "pipenv", "pdm"}
# Wrapper flags that take a separate value, so the value is not mistaken for the command.
_VALUE_FLAGS = {
    "-u", "--unset", "-n", "--adjust", "-s", "--signal", "-k", "--kill-after", "--with",
    "--with-requirements", "--with-editable", "-p", "--python", "--extra", "--group",
    "--directory", "--project", "--env-file", "--index", "--package", "--from", "-C", "-P",
}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}


def _strip_flags(out: list[str]) -> None:
    while out and out[0].startswith("-"):
        flag = out.pop(0)
        if flag in _VALUE_FLAGS and out:
            out.pop(0)


def _words(tokens: list[str]) -> list[str]:
    """Segment tokens with leading env assignments and wrappers removed.

    Wrappers are peeled in a loop so `env timeout 30 uv run python3 -c ...`
    lands on `python3` — the token that decides. Per-pattern patches for each
    wrapper were how `uv run phi-airgap run` slipped through.
    """
    out = list(tokens)
    while out:
        tok = out[0]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            out.pop(0)
        elif tok in _SKIP_TOKENS or tok == "env":
            out.pop(0)
            _strip_flags(out)
        elif tok == "timeout":
            out.pop(0)
            _strip_flags(out)
            if out:
                out.pop(0)  # the duration
        elif tok in _RUN_WRAPPERS and len(out) > 1 and out[1] == "run":
            del out[:2]
            _strip_flags(out)
        else:
            break
    # `python -m phi_airgap[.cli] ...` / `-m dbt ...` are the CLIs by another name.
    if out and _basename(out[0]) in _PY_RUNNER_NAMES and "-m" in out[1:4]:
        i = out.index("-m")
        if i + 1 < len(out):
            module = out[i + 1].split(".")[0]
            if module == "phi_airgap":
                out = ["phi-airgap", *out[i + 2 :]]
            elif module == "dbt":
                out = ["dbt", *out[i + 2 :]]
    return out


def _basename(tok: str) -> str:
    """Basename without pathlib: Path('.').name is '', which let `. ./.envrc`
    slip past the reader check entirely."""
    return tok.rsplit("/", 1)[-1] or tok


def _subcommand(words: list[str]) -> str:
    """First non-flag argument — the subcommand of `phi-airgap`/`dbt`/`security`."""
    return next((w for w in words[1:] if not w.startswith("-")), "")


def _read_local(tok: str) -> str:
    p = Path(os.path.expanduser(tok.strip("'\"")))
    try:
        if p.is_file() and p.stat().st_size < 512_000:
            return p.read_text(errors="replace")
    except OSError:
        pass
    return ""


def _script_payload(words: list[str]) -> str:
    """Contents of every local file named in argument position. Interpreters
    ignore extensions (`python3 evil.xyz` runs), so the inspector must too."""
    return "\n".join(filter(None, (_read_local(w) for w in words)))


def _warehouse_http(code: str) -> bool:
    """True if a curl/wget/nc/http segment targets the configured warehouse host."""
    host = _warehouse_host()
    if not host:
        return False
    return bool(
        re.search(
            rf"\b(?:curl|wget|http|httpie|nc)\b[^;&|]*{re.escape(host)}", code, re.IGNORECASE
        )
    )


def _check_bash(command: str, depth: int = 0) -> str | None:
    """Return a deny reason, or None to allow.

    Decisions are made per execution segment, on the token in COMMAND position.
    A command that merely mentions `phi-airgap refresh` or `.env` inside a heredoc or
    a commit message is not executing it, and blocking that made the hook
    unusable for writing about the phi-airgap.
    """
    if depth > 5:  # a script that sources itself
        return "Script indirection too deep to inspect. " + _PROTOCOL
    code, heredocs = _split_heredocs(command)

    if _warehouse_http(code):
        return "Direct HTTP calls to the warehouse are blocked. " + _PROTOCOL

    for tokens in _segments(code):
        words = _words(tokens)
        if not words:
            continue
        exe = _basename(words[0])
        sub = _subcommand(words)
        # Quote-stripped text of this segment, for the path/redirect patterns.
        seg = " ".join(words)

        if exe in _SQL_CLIENTS:
            return (
                "The warehouse SQL client is blocked — you must not execute queries. "
                + _PROTOCOL
            )

        # Script indirection: a shell reading a script file or a heredoc is
        # executing shell code; judge that code as if it were typed here.
        if exe in _SHELLS or exe in ("source", ".") or words[0].startswith("./") \
                or exe.endswith(".sh"):
            if exe in _SHELLS:
                i = next(
                    (i for i, w in enumerate(words[1:], 1) if re.match(r"^-\w*c\w*$", w)), None
                )
                if i is not None and i + 1 < len(words):
                    if r := _check_bash(words[i + 1], depth + 1):
                        return r
                if heredocs and (r := _check_bash(heredocs, depth + 1)):
                    return r
            target = words[0] if exe not in _SHELLS and exe not in ("source", ".") else sub
            if target and (body := _read_local(target)):
                if r := _check_bash(body, depth + 1):
                    return r + f" (inside {target})"

        if _writes_protected(words):
            return _PROTECTED_REASON + " " + _PROTOCOL

        if exe == "security" and _KEYCHAIN_READ.search(seg):
            # The one exception is the service named by config
            # `readable_keychain_service`, for a credential that reaches no
            # sensitive data. Empty config → every read is denied.
            svc = _readable_service()
            allowed = bool(svc) and (f"-s {svc}" in seg or f"--service {svc}" in seg)
            if not allowed:
                readable = f"Only `-s {svc}` is readable. " if svc else ""
                return (
                    "Reading a credential out of Keychain is blocked — it is deliberately "
                    f"outside your reach. {readable}" + _PROTOCOL
                )

        if exe == "dbt" and sub in _DBT_BLOCKED:
            return f"`dbt {sub}` prints result rows and is blocked. " + _PROTOCOL

        if exe in ("phi-airgap", "pq"):  # `pq` is the packaged short alias
            if sub in _PQ_BLOCKED:
                return (
                    f"`phi-airgap {sub}` is the human's command to run, not yours. " + _PROTOCOL
                )
            if sub == "refresh" and "--offline" not in words:
                return (
                    "`phi-airgap refresh` queries information_schema over the network, so the "
                    "user runs it. `phi-airgap refresh --offline` (dbt manifest only) is yours. "
                    + _PROTOCOL
                )
            # `phi-airgap dbt show` — the blocked subcommand sits one level in.
            if sub == "dbt" and _subcommand(words[words.index("dbt") :]) in _DBT_BLOCKED:
                return "`dbt show`/`run-operation` print result rows. " + _PROTOCOL
            continue  # every other phi-airgap subcommand is on the allowlist

        # Credential files: only when something would actually read or write one.
        if (exe in _READERS and _denied_envfile(seg)) or _ENVFILE_REDIRECT.search(seg):
            return (
                "That env file is blocked — env files hold credentials, and writing into "
                "one persists a secret to a dotfile. `.env.example`/`.template`/`.sample` "
                "are readable. `phi-airgap doctor` checks credential hygiene. " + _PROTOCOL
            )

        if exe in _INTERPRETERS or exe.endswith((".py", ".js", ".rb", ".pl")):
            payload = seg + "\n" + heredocs + "\n" + _script_payload(words)
            if m := _PY_FORBIDDEN.search(payload):
                return (
                    f"This interpreter invocation reaches live data or a credential "
                    f"(matched {m.group(0)!r}). " + _PROTOCOL
                )
            host = _warehouse_host()
            if host and host.lower() in payload.lower():
                return "This interpreter invocation names the warehouse host. " + _PROTOCOL

    return None


# --- Read patterns -----------------------------------------------------------

_READ_DENY = [
    (re.compile(r"\.parquet$", re.IGNORECASE), "Parquet extracts may hold row-grain PHI."),
    (re.compile(r"\.duckdb$", re.IGNORECASE), "DuckDB files may hold row-grain PHI."),
    (
        re.compile(r"/\.phi-airgap/out/[^/]*\.raw\.", re.IGNORECASE),
        "That is the pre-scrub result. Read the scrubbed .csv/.json instead.",
    ),
    (
        re.compile(r"(?:^|/)\.envrc$"),
        "Credential file.",
    ),
    (
        re.compile(r"(?:^|/)\.env(?!\.example|\.template|\.sample)(?:\.[\w-]+)?$"),
        "Credential file. `.env.example`/`.template`/`.sample` are readable.",
    ),
]


def _check_read(path: str) -> str | None:
    for pattern, why in _READ_DENY:
        if pattern.search(path):
            return f"{why} {_PROTOCOL}"
    return None


def _check_write(path: str) -> str | None:
    if _is_protected(path):
        return f"{_PROTECTED_REASON} {_PROTOCOL}"
    return _check_read(path)


def _deny(reason: str) -> None:
    print(f"[phi-airgap] BLOCKED: {reason}", file=sys.stderr)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def _fail_closed(why: str) -> None:
    """Exit 2: the harness blocks the tool and shows stderr to the agent."""
    print(f"[phi-airgap] hook failed closed: {why}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    debug = os.environ.get("CLAUDE_HOOKS_DEBUG")

    # ponytail: plain blocking stdin read; the harness always pipes the event
    # and closes stdin, so no timeout wrapper is needed.
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        _fail_closed("input is not JSON")
    if not isinstance(event, dict) or not isinstance(event.get("tool_input", {}) or {}, dict):
        _fail_closed("unexpected event shape")

    if _BYPASS_FILE.exists():
        print(f"[phi-airgap] BYPASSED: {_BYPASS_FILE} exists", file=sys.stderr)
        sys.exit(0)

    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}

    if tool in ("Read", "Grep"):
        reason = _check_read(str(tool_input.get("file_path") or tool_input.get("path") or ""))
    elif tool in ("Write", "Edit", "MultiEdit"):
        reason = _check_write(str(tool_input.get("file_path", "")))
    else:
        command = tool_input.get("command", "")
        reason = _check_bash(command) if command else None

    if reason:
        _deny(reason)

    if debug:
        print(f"[phi-airgap] {tool} allowed through", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        if os.environ.get("CLAUDE_HOOKS_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        else:
            print(f"[phi-airgap] Error: {type(e).__name__}: {e}", file=sys.stderr)
        # A crashed hook fails CLOSED unless the human opted out in config.
        if _config_value("hook_fail_open", "false").lower() == "true":
            sys.exit(0)
        sys.exit(2)
