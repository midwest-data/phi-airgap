"""phi-airgap — the PHI-airgap query broker.

A sanctioned path from an LLM coding agent to a sensitive SQL warehouse: the
agent writes SQL; the human runs `phi-airgap run`; the agent reads the scrubbed
output. Patient/row-grain data never reaches the model.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

from . import util

BANNER = "phi-airgap — PHI-airgap query broker. Reduces disclosure risk; not HIPAA compliance."

# dbt subcommands that print result rows. Blocked regardless of allow_claude_dbt.
DBT_BLOCKED = {"show", "run-operation"}

# Where the enforcement hook is expected once installed, and where it ships from.
HOOK_INSTALL_PATH = Path.home() / ".claude/hooks/pretool-phi-airgap.py"
HOOK_PACKAGED = util.DATA / "pretool-phi-airgap.py"
SETTINGS = Path.home() / ".claude/settings.json"
HOOK_MATCHER = "Bash|Read|Write|Edit|MultiEdit|Grep"
HOOK_ENTRY = {"type": "command", "command": f"python3 {HOOK_INSTALL_PATH}"}


# --- subcommands -------------------------------------------------------------


def cmd_run(args) -> int:
    from . import run

    path = Path(args.file)
    if not path.exists():
        util.die(f"{path} not found. The agent writes SQL to .phi-airgap/q.sql.")
    return run.run_file(path, purpose=args.purpose)


def cmd_check(args) -> int:
    """Run the gate WITHOUT executing. No network, no credential, no rows.

    On the agent's allowlist on purpose: it lets the agent confirm its SQL will
    pass before asking the user to run it, which removes the round-trip that
    would otherwise tempt a shortcut.
    """
    from . import gate, meta

    path = Path(args.file)
    if not path.exists():
        util.die(f"{path} not found")
    index = meta.load() if meta.cache_path().exists() else None
    sql = path.read_text()
    v = gate.check(sql, util.policy(), index)

    print(f"{'ALLOW' if v.allowed else 'DENY '} [{v.worst}]  {path}")
    for table, level in sorted(v.tables.items()):
        print(f"    {level:<6} {table}")
    for r in v.reasons:
        print(f"  - {r}")
    if v.allowed:
        print(f"\nGate only — no data was read. Ask the user to run:  ! phi-airgap run {path}")
    util.audit(
        event="check", source=str(path), verdict="ALLOW" if v.allowed else "DENY",
        classification=v.worst, reasons=v.reasons, sql=sql.strip(),
        sql_sha256=hashlib.sha256(sql.encode()).hexdigest(), group_keys=sorted(v.group_keys),
        user=getpass.getuser(), host=socket.gethostname(),
    )
    return 0 if v.allowed else 1


def cmd_schema(args) -> int:
    from . import meta

    hits = meta.find(args.pattern)
    print(meta.render(hits, columns_only=args.columns_only))
    if not args.columns_only:
        print(f"({len(hits)} relations matched `{args.pattern}` — local cache, no network)")
    return 0 if hits else 1


def cmd_refresh(args) -> int:
    from . import meta

    manifests = [Path(p).expanduser() for p in args.manifest] or _default_manifests()
    if args.stats and args.offline:
        util.die("--stats needs the warehouse; drop --offline.")
    index = meta.build(manifests, offline=args.offline, stats=args.stats)
    if not index:
        util.die("Nothing to cache — no manifest found and no catalog reachable.")
    path = meta.save(index)
    cols = sum(len(e.get("columns", {})) for e in index.values())
    print(f"phi-airgap: cached {len(index)} relations / {cols} columns -> {path}")

    if args.draft_policy:
        draft = util.root() / "policy.draft.yml"
        draft.write_text(meta.draft_policy(index, util.policy()))
        print(f"phi-airgap: review sheet -> {draft}")
    util.audit(
        event="refresh", relations=len(index), columns=cols, offline=args.offline,
        stats=args.stats,
    )
    return 0


def _default_manifests() -> list[Path]:
    root = util.root()
    return sorted(root.glob("*/target/manifest.json")) + sorted(
        root.glob("*/*/target/manifest.json")
    )


# dbt subcommands that materialise a relation. Their targets may not be GREEN.
DBT_WRITES = {"run", "build", "seed", "snapshot"}
_SELECT_FLAGS = {"--select", "-s", "--models", "-m", "--model"}


def _dbt_selectors(argv: list[str]) -> list[str]:
    out: list[str] = []
    take = False
    for a in argv:
        if a in _SELECT_FLAGS:
            take = True
            continue
        if a.startswith(tuple(f + "=" for f in _SELECT_FLAGS)):
            out.extend(a.split("=", 1)[1].split())
            continue
        if a.startswith("-"):
            take = False
            continue
        if take:
            out.extend(a.split())
    return out


def _green_dbt_targets(selectors: list[str]) -> list[str]:
    """Relations a dbt write would materialise that classify GREEN, or the
    reason the check cannot be made. GREEN is exempt from every aggregation
    rule, so a relation the agent can build must never be GREEN."""
    from . import gate, meta

    if not meta.cache_path().exists():
        util.die("no metadata cache — run `phi-airgap refresh --offline` before `dbt run`.", 1)
    index = meta.load()
    pol = util.policy()
    if not selectors:  # a whole-project run touches every model
        hits = {k: v for k, v in index.items() if v.get("kind") in ("model", "seed", "snapshot")}
    else:
        hits = {}
        for sel in selectors:
            name = re.sub(r"^[@+\d]*|[+]\d*$", "", sel)
            if ":" in name or not name:
                util.die(
                    f"selector `{sel}` cannot be resolved to relations — use model names, "
                    "so each target can be classified.",
                    1,
                )
            found = meta.find(name, index)
            if not found:
                util.die(
                    f"`{sel}` is not in the metadata cache — run `phi-airgap refresh --offline`.",
                    1,
                )
            hits.update(found)
    green = []
    for key in hits:
        cat, sch, tbl = (["", ""] + key.split("."))[-3:]
        if gate.classify(cat, sch, tbl, pol) == "GREEN":
            green.append(key)
    return green


def cmd_dbt(args) -> int:
    from . import scrub

    cfg = util.config()
    argv = args.dbt_args
    sub = next((a for a in argv if not a.startswith("-")), "")
    if sub in DBT_BLOCKED:
        util.die(f"`dbt {sub}` prints result rows and is blocked by the phi-airgap.", 1)
    if not cfg.get("allow_claude_dbt", True) and os.environ.get("CLAUDECODE"):
        util.die("allow_claude_dbt is false in config.yml — the human must run dbt.", 1)
    if sub in DBT_WRITES and (green := _green_dbt_targets(_dbt_selectors(argv))):
        util.die(
            f"`dbt {sub}` would materialise a GREEN relation: {', '.join(green)}. GREEN is "
            "exempt from aggregation, so the agent may not build it. The human runs this.",
            1,
        )

    env = dict(os.environ, DATABRICKS_TOKEN=util.keychain_get())
    proc = subprocess.run(
        ["dbt", *argv], env=env, capture_output=True, text=True, cwd=args.cwd or None
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    try:
        cleaned, det, ner = scrub.scrub_text(text)
    except Exception as e:
        # Never print unscrubbed dbt output: fall back to the regex layer, which
        # needs no spaCy and still removes tokens and identifier shapes.
        cleaned, det, ner = (*scrub.scrub_text(text, run_ner=False)[:2], [])
        print(f"phi-airgap: warning — NER unavailable ({type(e).__name__}: {e})", file=sys.stderr)
    print(cleaned)
    if det:
        print(
            f"\n*** PHI ALARM *** dbt output contained {', '.join(det)} — redacted. "
            "dbt should never print identifiers; investigate the model.",
            file=sys.stderr,
        )
    util.audit(event="dbt", args=argv, returncode=proc.returncode, identifiers=det, names=ner)
    return proc.returncode


def cmd_scrub(args) -> int:
    from . import scrub

    path = Path(args.file)
    text = path.read_text(errors="replace")
    cleaned, det, ner = scrub.scrub_text(text)
    if args.check:
        pass  # --check reports only; never rewrites and never echoes content
    elif args.in_place:
        path.write_text(cleaned)
        print(f"phi-airgap: scrubbed in place -> {path}")
    else:
        sys.stdout.write(cleaned)
    if det:
        print(f"phi-airgap: IDENTIFIERS in {path}: {', '.join(det)}", file=sys.stderr)
    if ner:
        print(
            f"phi-airgap: possible names in {path}: {', '.join(ner)} (advisory — spaCy fires on "
            "ordinary prose; eyeball it)",
            file=sys.stderr,
        )
    if not det and not ner:
        print(f"phi-airgap: clean: {path}", file=sys.stderr)
    util.audit(event="scrub", file=str(path), identifiers=det, names=ner)
    # --check exits 1 only on deterministic identifier matches, so it is usable
    # as a gate. Without --check the exit code stays 0 for pipe-friendliness.
    return 1 if (args.check and det) else 0


# --- pq git: PHI screen for commits and pushes --------------------------------

_GIT_HOOK_MARK = "# phi-airgap git hook v1"
_GIT_HOOKS = {
    "pre-commit": "exec pq git scan --staged --no-ner",  # fast: regex floor only
    "pre-push": "exec pq git scan --pre-push",  # NER advisory on; commit messages too
}


def _git_hook_body(name: str) -> str:
    return (
        f"#!/bin/sh\n{_GIT_HOOK_MARK} — do not edit; `pq git uninstall` removes it\n"
        f"{_GIT_HOOKS[name]} \"$@\"\n"
    )


def _is_our_git_hook(path: Path) -> bool:
    try:
        return _GIT_HOOK_MARK in path.read_text(errors="replace")
    except OSError:
        return False


def cmd_git_scan(args) -> int:
    from . import gitscan

    try:
        root = gitscan.repo_root()
    except RuntimeError as e:
        util.die(str(e))
    globs = gitscan.load_ignore(root)
    run_ner = not args.no_ner
    allow_unscannable = args.allow_unscannable or not util.config().get(
        "git_unscannable_blocks", True
    )

    # (path, bytes-loader) pairs plus any commit messages to scan as text.
    targets: list[tuple[str, object]] = []
    messages: list[tuple[str, str]] = []
    try:
        if args.pre_push:
            for revs, tip in gitscan.push_ranges(sys.stdin.read()):
                label = " ".join(revs)
                targets += [(p, (lambda p=p, tip=tip: gitscan.commit_blob(tip, p)))
                            for p in gitscan.range_files(revs)]
                messages.append((f"<commit messages {label}>", gitscan.range_messages(revs)))
        elif args.range:
            if ".." not in args.range:
                util.die("--range takes A..B")
            tip = args.range.split("..")[-1]
            targets += [(p, (lambda p=p: gitscan.commit_blob(tip, p)))
                        for p in gitscan.range_files([args.range])]
            messages.append((f"<commit messages {args.range}>",
                             gitscan.range_messages([args.range])))
        elif args.all:
            targets += [(p, (lambda p=p: (root / p).read_bytes())) for p in gitscan.all_files()]
        elif args.paths:
            targets += [(p, (lambda p=p: Path(p).read_bytes())) for p in args.paths]
        else:
            targets += [(p, (lambda p=p: gitscan.staged_blob(p))) for p in gitscan.staged_files()]
    except RuntimeError as e:
        util.die(str(e))

    results: list[gitscan.FileResult] = []
    for path, load in targets:
        if gitscan.ignored(path, globs):
            continue
        try:
            data = load()
        except (OSError, RuntimeError) as e:
            results.append(gitscan.FileResult(path, unscannable=f"unreadable: {e}"))
            continue
        results.append(gitscan.scan_blob(path, data, run_ner=run_ner))
    for label, text in messages:
        if text.strip():
            results.append(gitscan.scan_text(label, text, run_ner=run_ner))

    det = sorted({k for r in results for _, kinds in r.hits for k in kinds})
    ner = sorted({k for r in results for k in r.ner})
    unscannable = [r for r in results if r.unscannable]
    blocked = bool(det) or (bool(unscannable) and not allow_unscannable) or (
        args.strict and bool(ner)
    )

    if args.json:
        print(json.dumps([r.__dict__ for r in results]))
    err = sys.stderr
    for r in results:
        for no, kinds in r.hits:
            print(f"phi-airgap: {r.path}:{no}  {', '.join(kinds)}", file=err)
        if r.ner:
            print(f"phi-airgap: advisory: {r.path}  possible {', '.join(r.ner)}", file=err)
        if r.unscannable:
            print(f"phi-airgap: unscannable: {r.path}  {r.unscannable}", file=err)
    n_hit = sum(1 for r in results if r.hits)
    print(
        f"phi-airgap: git scan: {len(results)} file(s), {n_hit} with identifiers, "
        f"{len(unscannable)} unscannable"
        + (f", possible names in {sum(1 for r in results if r.ner)}" if ner else ""),
        file=err,
    )
    if blocked:
        print(
            "phi-airgap: blocked — a false positive? put `phi-airgap: allow` on that line "
            f"(or `phi-airgap: allow-file` in the first 20 lines), or add a glob to "
            f"{gitscan.IGNORE_FILE}. Unscannable files: --allow-unscannable for one run.",
            file=err,
        )
    util.audit(
        event="git-scan", files=len(results), identifiers=det, names=ner,
        unscannable=[r.path for r in unscannable], blocked=blocked,
    )
    return 1 if blocked else 0


def cmd_git_install(args) -> int:
    from . import gitscan

    try:
        hooks = gitscan.hooks_dir()
    except RuntimeError as e:
        util.die(str(e))
    hooks.mkdir(parents=True, exist_ok=True)
    for name in _GIT_HOOKS:
        dst = hooks / name
        if dst.exists() and not _is_our_git_hook(dst):
            if not args.force:
                util.die(
                    f"{dst} exists and is not ours. Chain it yourself, or rerun with --force "
                    f"(backs it up to {name}.bak)."
                )
            dst.rename(dst.with_name(f"{name}.bak"))
            print(f"phi-airgap: backed up existing {name} -> {name}.bak")
        dst.write_text(_git_hook_body(name))
        dst.chmod(0o755)
        print(f"phi-airgap: installed {dst}")
    print(
        "phi-airgap: commits and pushes are now screened. History before today was not — "
        "run `pq git scan --all` once."
    )
    util.audit(event="git-install", hooks=str(hooks))
    return 0


def cmd_git_uninstall(args) -> int:
    from . import gitscan

    try:
        hooks = gitscan.hooks_dir()
    except RuntimeError as e:
        util.die(str(e))
    for name in _GIT_HOOKS:
        dst = hooks / name
        if dst.exists() and _is_our_git_hook(dst):
            dst.unlink()
            print(f"phi-airgap: removed {dst}")
        elif dst.exists():
            print(f"phi-airgap: left {dst} alone (not ours)")
    util.audit(event="git-uninstall", hooks=str(hooks))
    return 0


def _git_hooks_installed() -> bool | None:
    """True/False for the cwd's repo, None when cwd is not a git repo."""
    from . import gitscan

    try:
        hooks = gitscan.hooks_dir()
    except RuntimeError:
        return None
    return all(_is_our_git_hook(hooks / n) for n in _GIT_HOOKS)


def cmd_doctor(args) -> int:
    cfg = util.config()
    problems = 0

    def check(ok: bool, label: str, fix: str = "") -> None:
        nonlocal problems
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            problems += 1
            if fix:
                print(f"        -> {fix}")

    print(f"{BANNER}\n\nroot: {util.root()}\n")

    print("credentials")
    svc = cfg["keychain_service"]
    check(
        util.keychain_has(svc),
        f"Keychain entry '{svc}' present",
        f'security add-generic-password -a "$USER" -s {svc} -w',
    )

    print("\nharness hook")
    check(HOOK_INSTALL_PATH.exists(), f"{HOOK_INSTALL_PATH} exists", "phi-airgap init")
    if HOOK_INSTALL_PATH.exists():
        installed, packaged = _hook_version(HOOK_INSTALL_PATH), _hook_version(HOOK_PACKAGED)
        check(
            HOOK_INSTALL_PATH.read_bytes() == HOOK_PACKAGED.read_bytes(),
            f"installed hook matches packaged (installed {installed}, packaged {packaged})",
            "phi-airgap init --force-hook",
        )
        check(
            _hook_denies(HOOK_INSTALL_PATH, "phi-airgap run x.sql"),
            "installed hook denies `phi-airgap run` when actually invoked",
        )
        check(
            _hook_exit(HOOK_INSTALL_PATH, "not json") != 0,
            "installed hook fails closed on malformed input",
            "set hook_fail_open: false in config.yml",
        )
    bypass = util.HOME_DIR / "BYPASS"
    check(not bypass.exists(), f"no bypass file at {bypass}", f"rm {bypass}")
    if (git_hooks := _git_hooks_installed()) is not None:
        check(git_hooks, "git pre-commit/pre-push PHI screen installed in this repo",
              "pq git install")
    registered = False
    if SETTINGS.exists():
        registered = "pretool-phi-airgap.py" in SETTINGS.read_text()
    check(registered, f"hook registered in {SETTINGS}", "phi-airgap init")

    print("\npolicy + cache")
    check(util.POLICY_FILE.exists(), f"policy: {util.POLICY_FILE}")
    check(
        util.POLICY_FILE.parent != util.DATA,
        "policy is a reviewed copy, not the packaged example",
        "phi-airgap init, then edit ~/.phi-airgap/policy.yml",
    )
    from . import meta

    cache = meta.cache_path()
    check(cache.exists(), f"metadata cache {cache}", "phi-airgap refresh")

    print("\naudit log")
    ws_log, home_log = util.phi_airgap_dir() / "log.jsonl", util.home_audit_path()
    for label, path in (("workspace", ws_log), ("home mirror", home_log)):
        ok, line = util.verify_chain(path)
        check(ok, f"{label} chain intact: {path}" + ("" if ok else f" (breaks at line {line})"),
              "the log was edited or truncated — investigate before trusting the banner")
    check(
        util.tails_match(),
        "workspace log and home mirror agree on the last entry",
        "the workspace log was rewritten; the home mirror is the record",
    )

    print("\nplaintext secrets on disk")
    for path, hits in _scan_secrets(util.root()):
        check(False, f"{path}: {hits}", "move to Keychain, then rotate the credential")
    if not _scan_secrets(util.root()):
        check(True, f"no token-shaped strings under {util.root()}")

    transcripts = _scan_secrets(Path.home() / ".claude/projects", limit=3)
    check(
        not transcripts,
        "no tokens in Claude Code transcripts",
        "past transcripts recorded live tokens — rotate them; "
        f"e.g. {transcripts[0][0] if transcripts else ''}",
    )

    print(f"\n{problems} problem(s).")
    util.audit(event="doctor", problems=problems)
    return 1 if problems else 0


def _hook_version(path: Path) -> str:
    m = re.search(r"^# hook-version:\s*(\S+)", path.read_text(errors="replace"), re.M)
    return m.group(1) if m else "unknown"


def _hook_exit(hook: Path, stdin: str) -> int:
    try:
        return subprocess.run(
            [sys.executable, str(hook)], input=stdin, capture_output=True, text=True, timeout=20
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _hook_denies(hook: Path, command: str) -> bool:
    """Run the installed hook on one Bash payload; True if it printed a deny."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    try:
        r = subprocess.run(
            [sys.executable, str(hook)], input=payload, capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return '"deny"' in r.stdout


_SECRET_SCAN = re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}")
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".phi-airgap",
    "dbt_packages",
}


def _scan_secrets(base: Path, limit: int = 40) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not base.exists():
        return out
    for path in base.rglob("*"):
        if len(out) >= limit:
            break
        if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            if path.stat().st_size > 20_000_000:
                continue
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        kinds = {m.group(0)[:4] for m in _SECRET_SCAN.finditer(text)}
        if kinds:
            out.append((str(path), " ".join(f"{k}…" for k in sorted(kinds))))
    return out


_POINTER = (
    "# {key} removed by `phi-airgap adopt` on the PHI phi-airgap.\n"
    "# The value now lives in the macOS Keychain under service `{service}`,\n"
    "# where the agent cannot read it. Run commands through `phi-airgap` (which injects it),\n"
    "# or in a shell:\n"
    "#   export {key}=$(security find-generic-password -a \"$USER\" -s {service} -w)\n"
)


def cmd_adopt(args) -> int:
    """Move a plaintext token out of an env file and into Keychain, in one step.

    This is the step that actually removes the exposure. Everything else in the
    phi-airgap reduces risk; this eliminates a readable credential.
    """
    path = Path(args.file).expanduser()
    if not path.exists():
        util.die(f"{path} not found")
    service = args.service or util.config()["keychain_service"]

    text = path.read_text()
    pattern = re.compile(
        rf"^(?:export\s+)?{re.escape(args.key)}\s*=\s*['\"]?(\S+?)['\"]?\s*$", re.MULTILINE
    )
    m = pattern.search(text)
    if not m:
        util.die(f"No non-empty {args.key}= line in {path}")
    secret = m.group(1)

    r = subprocess.run(
        ["security", "add-generic-password", "-U", "-a", getpass.getuser(), "-s", service,
         "-w", secret, "-D", "phi-airgap PHI broker", "-j", f"adopted from {path}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        util.die(f"Keychain write failed: {r.stderr.strip()}")

    if util.keychain_get(service) != secret:
        util.die("Keychain round-trip mismatch — the file was NOT modified.")

    backup = path.with_suffix(path.suffix + ".pre-airgap")
    backup.write_text(text)
    backup.chmod(0o600)
    path.write_text(pattern.sub(_POINTER.format(key=args.key, service=service).rstrip(), text))

    print(
        f"phi-airgap: {args.key} -> Keychain service '{service}' (verified)\n"
        f"phi-airgap: {path} rewritten with a pointer comment\n"
        f"phi-airgap: plaintext backup at {backup} — DELETE IT once you have confirmed things "
        "work:\n"
        f"      rm '{backup}'\n"
        f"phi-airgap: this token has appeared in shell history and past transcripts. ROTATE IT."
    )
    util.audit(event="adopt", file=str(path), key=args.key, service=service)
    return 0


def cmd_selftest(args) -> int:
    """Run the red-team suite. Exposed as a subcommand so it is runnable without
    naming a .py file that the harness hook (rightly) refuses to execute."""
    from . import selftest

    return selftest.main()


def cmd_init(args) -> int:
    """Copy the example config/policy to ~/.phi-airgap/ (never overwriting),
    install the hook, and register it in ~/.claude/settings.json."""
    import shutil

    util.HOME_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("config", "policy"):
        dst = util.HOME_DIR / f"{name}.yml"
        if dst.exists():
            print(f"phi-airgap: kept existing {dst}")
        else:
            shutil.copy(util.DATA / f"{name}.example.yml", dst)
            print(f"phi-airgap: wrote {dst} — EDIT IT before use")

    HOOK_INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
    if HOOK_INSTALL_PATH.exists() and not args.force_hook:
        if HOOK_INSTALL_PATH.read_bytes() != HOOK_PACKAGED.read_bytes():
            print(
                f"phi-airgap: {HOOK_INSTALL_PATH} differs from packaged — rerun with --force-hook"
            )
    else:
        shutil.copy(HOOK_PACKAGED, HOOK_INSTALL_PATH)
        HOOK_INSTALL_PATH.chmod(0o755)
        print(f"phi-airgap: installed hook -> {HOOK_INSTALL_PATH}")

    data = json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}
    blocks = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    ours = [
        b for b in blocks
        if any("pretool-phi-airgap" in h.get("command", "") for h in b.get("hooks", []))
    ]
    if ours and ours[0].get("matcher") == HOOK_MATCHER:
        print(f"phi-airgap: hook already registered in {SETTINGS}")
    else:
        for b in ours:
            blocks.remove(b)
        blocks.append({"matcher": HOOK_MATCHER, "hooks": [HOOK_ENTRY]})
        SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS.write_text(json.dumps(data, indent=2) + "\n")
        print(f"phi-airgap: registered hook in {SETTINGS} (matcher {HOOK_MATCHER})")
    util.audit(event="init")
    return 0


def cmd_log(args) -> int:
    path = util.phi_airgap_dir() / "log.jsonl"
    if not path.exists():
        print("phi-airgap: no audit log yet")
        return 0
    lines = path.read_text().splitlines()[-args.tail :]
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        head = f"{e.get('ts', '')}  {e.get('event', ''):<8} {e.get('verdict', ''):<10}"
        detail = e.get("source") or " ".join(map(str, e.get("args", []))) or e.get("file", "")
        sha = e.get("sql_sha256", "")[:8]
        who = " ".join(x for x in (sha, e.get("user", ""), e.get("purpose", "")) if x)
        print(f"{head} {detail}" + (f"  [{who}]" if who else ""))
        for r in e.get("reasons", [])[:3]:
            print(f"    - {r}")
    return 0


def cmd_uninstall(args) -> int:
    """Teardown. Restores nothing automatically — it prints what to do, then
    removes the harness hook and the CLAUDE.md block. The audit log survives."""
    settings = Path.home() / ".claude/settings.json"
    if settings.exists():
        data = json.loads(settings.read_text())
        blocks = data.get("hooks", {}).get("PreToolUse", [])
        for block in blocks:
            block["hooks"] = [
                h
                for h in block.get("hooks", [])
                if "pretool-phi-airgap" not in h.get("command", "")
            ]
        data["hooks"]["PreToolUse"] = [b for b in blocks if b.get("hooks")]
        settings.write_text(json.dumps(data, indent=2))
        print(f"phi-airgap: removed the hook from {settings}")

    md = util.root() / "CLAUDE.md"
    if md.exists():
        text = md.read_text()
        new = re.sub(
            r"\n<!-- phi-airgap:start -->.*?<!-- phi-airgap:end -->\n",
            "\n",
            text,
            flags=re.DOTALL,
        )
        if new != text:
            md.write_text(new)
            print(f"phi-airgap: removed the protocol block from {md}")

    print(
        "\nphi-airgap: the Keychain entry and .phi-airgap/log.jsonl were left in place on purpose "
        "(audit record of the interim period). To put the token back in a file:\n"
        f'  echo "DATABRICKS_TOKEN=$(security find-generic-password -a "$USER" '
        f"-s {util.config()['keychain_service']} -w)\" >> .env\n"
        "Then: uv tool uninstall phi-airgap"
    )
    util.audit(event="uninstall")
    return 0


# --- wiring ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog=Path(sys.argv[0]).name or "phi-airgap", description=BANNER)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="gate, execute and scrub a .sql file")
    r.add_argument("file")
    r.add_argument("--purpose", help="why this query is being run (recorded in the audit log)")
    r.set_defaults(fn=cmd_run)

    k = sub.add_parser("check", help="run the gate on a .sql file without executing it")
    k.add_argument("file")
    k.set_defaults(fn=cmd_check)

    s = sub.add_parser("schema", help="column list from the local cache (no network)")
    s.add_argument("pattern")
    s.add_argument("--columns-only", action="store_true")
    s.set_defaults(fn=cmd_schema)

    f = sub.add_parser("refresh", help="rebuild the metadata cache")
    f.add_argument("--offline", action="store_true", help="dbt manifest only, no warehouse")
    f.add_argument("--manifest", action="append", default=[], help="path to a dbt manifest.json")
    f.add_argument("--draft-policy", action="store_true", help="write policy.draft.yml for review")
    f.add_argument(
        "--stats", action="store_true",
        help="also count rows and distinct values per column (activates gate rule R14; "
        "one count(*)/count(distinct) statement per relation, can be slow on raw tables)",
    )
    f.set_defaults(fn=cmd_refresh)

    d = sub.add_parser("dbt", help="dbt wrapper: Keychain token, no show/run-operation")
    d.add_argument("--cwd")
    d.add_argument("dbt_args", nargs=argparse.REMAINDER)
    d.set_defaults(fn=cmd_dbt)

    a = sub.add_parser("adopt", help="move a plaintext token from an env file into Keychain")
    a.add_argument("file", help="path to the .env / .envrc holding the secret")
    a.add_argument("key", help="variable name, e.g. DATABRICKS_TOKEN")
    a.add_argument("--service", help="Keychain service name (default: config keychain_service)")
    a.set_defaults(fn=cmd_adopt)

    c = sub.add_parser("scrub", help="run the scrubber over any file")
    c.add_argument("file")
    c.add_argument("-i", "--in-place", action="store_true")
    c.add_argument(
        "--check",
        action="store_true",
        help="report only; exit 1 on identifier matches, names are advisory (no rewrite)",
    )
    c.set_defaults(fn=cmd_scrub)

    gi = sub.add_parser("git", help="PHI screen for commits and pushes (hooks + scanner)")
    gsub = gi.add_subparsers(dest="git_cmd", required=True)
    gs = gsub.add_parser(
        "scan", help="screen files for identifiers; default: the staged files"
    )
    gs.add_argument("paths", nargs="*", help="worktree files (what pre-commit.com passes)")
    gs.add_argument("--staged", action="store_true", help="the index (default)")
    gs.add_argument("--range", help="commits A..B: files changed, at B, plus the messages")
    gs.add_argument("--pre-push", action="store_true", help="read the pre-push hook's stdin")
    gs.add_argument("--all", action="store_true", help="every tracked file")
    gs.add_argument("--strict", action="store_true", help="possible names (NER) also block")
    gs.add_argument("--no-ner", action="store_true", help="regex floor only (fast)")
    gs.add_argument(
        "--allow-unscannable", action="store_true",
        help="do not block on files whose text cannot be extracted",
    )
    gs.add_argument("--json", action="store_true", help="machine-readable results on stdout")
    gs.set_defaults(fn=cmd_git_scan)
    gin = gsub.add_parser("install", help="write pre-commit + pre-push hooks into this repo")
    gin.add_argument("--force", action="store_true", help="replace foreign hooks (kept as .bak)")
    gin.set_defaults(fn=cmd_git_install)
    gsub.add_parser("uninstall", help="remove the hooks this tool wrote").set_defaults(
        fn=cmd_git_uninstall
    )

    i = sub.add_parser(
        "init", help="copy example config/policy to ~/.phi-airgap and install the hook"
    )
    i.add_argument("--force-hook", action="store_true", help="overwrite an existing installed hook")
    i.set_defaults(fn=cmd_init)

    sub.add_parser("doctor", help="verify the phi-airgap is intact").set_defaults(fn=cmd_doctor)
    sub.add_parser("selftest", help="red-team the gate, scrubber and hook").set_defaults(
        fn=cmd_selftest
    )

    g = sub.add_parser("log", help="the audit trail")
    g.add_argument("--tail", type=int, default=40)
    g.set_defaults(fn=cmd_log)

    sub.add_parser("uninstall", help="full teardown").set_defaults(fn=cmd_uninstall)

    args = p.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
