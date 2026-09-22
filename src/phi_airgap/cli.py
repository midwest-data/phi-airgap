"""phi-airgap — the PHI-airgap query broker.

A sanctioned path from an LLM coding agent to a sensitive SQL warehouse: the
agent writes SQL; the human runs `phi-airgap run`; the agent reads the scrubbed
output. Patient/row-grain data never reaches the model.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import util

BANNER = "phi-airgap — PHI-airgap query broker. Reduces disclosure risk; not HIPAA compliance."

# dbt subcommands that print result rows. Blocked regardless of allow_claude_dbt.
DBT_BLOCKED = {"show", "run-operation"}

# Where the enforcement hook is expected once installed.
HOOK_INSTALL_PATH = Path.home() / ".claude/hooks/pretool-phi-airgap.py"


# --- subcommands -------------------------------------------------------------


def cmd_run(args) -> int:
    from . import run

    path = Path(args.file)
    if not path.exists():
        util.die(f"{path} not found. The agent writes SQL to .phi-airgap/q.sql.")
    return run.run_file(path)


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
    v = gate.check(path.read_text(), util.policy(), index)

    print(f"{'ALLOW' if v.allowed else 'DENY '} [{v.worst}]  {path}")
    for table, level in sorted(v.tables.items()):
        print(f"    {level:<6} {table}")
    for r in v.reasons:
        print(f"  - {r}")
    if v.allowed:
        print(f"\nGate only — no data was read. Ask the user to run:  ! phi-airgap run {path}")
    util.audit(event="check", source=str(path), verdict="ALLOW" if v.allowed else "DENY",
               classification=v.worst, reasons=v.reasons)
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
    index = meta.build(manifests, offline=args.offline)
    if not index:
        util.die("Nothing to cache — no manifest found and no catalog reachable.")
    path = meta.save(index)
    cols = sum(len(e.get("columns", {})) for e in index.values())
    print(f"phi-airgap: cached {len(index)} relations / {cols} columns -> {path}")

    if args.draft_policy:
        draft = util.root() / "policy.draft.yml"
        draft.write_text(meta.draft_policy(index, util.policy()))
        print(f"phi-airgap: review sheet -> {draft}")
    util.audit(event="refresh", relations=len(index), columns=cols, offline=args.offline)
    return 0


def _default_manifests() -> list[Path]:
    root = util.root()
    return sorted(root.glob("*/target/manifest.json")) + sorted(
        root.glob("*/*/target/manifest.json")
    )


def cmd_dbt(args) -> int:
    from . import scrub

    cfg = util.config()
    argv = args.dbt_args
    sub = next((a for a in argv if not a.startswith("-")), "")
    if sub in DBT_BLOCKED:
        util.die(f"`dbt {sub}` prints result rows and is blocked by the phi-airgap.", 1)
    if not cfg.get("allow_claude_dbt", True) and os.environ.get("CLAUDECODE"):
        util.die("allow_claude_dbt is false in config.yml — the human must run dbt.", 1)

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
    check(HOOK_INSTALL_PATH.exists(), f"{HOOK_INSTALL_PATH} exists")
    settings = Path.home() / ".claude/settings.json"
    registered = False
    if settings.exists():
        registered = "pretool-phi-airgap.py" in settings.read_text()
    check(registered, "hook registered in ~/.claude/settings.json")

    print("\npolicy + cache")
    check(util.POLICY_FILE.exists(), f"{util.POLICY_FILE} exists")
    from . import meta

    cache = meta.cache_path()
    check(cache.exists(), f"metadata cache {cache}", "phi-airgap refresh")

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


_SECRET_SCAN = re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}")
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".phi-airgap", "dbt_packages"}


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
    "# or in a shell:  export {key}=$(security find-generic-password -a \"$USER\" -s {service} -w)\n"
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
        ["security", "add-generic-password", "-U", "-a", os.environ["USER"], "-s", service,
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
        f"phi-airgap: plaintext backup at {backup} — DELETE IT once you have confirmed things work:\n"
        f"      rm '{backup}'\n"
        f"phi-airgap: this token has appeared in shell history and past transcripts. ROTATE IT."
    )
    util.audit(event="adopt", file=str(path), key=args.key, service=service)
    return 0


def cmd_selftest(args) -> int:
    """Run the red-team suite. Exposed as a subcommand so it is runnable without
    naming a .py file that the harness hook (rightly) refuses to execute."""
    tests_dir = util.REPO_ROOT / "tests"
    sys.path.insert(0, str(tests_dir))
    import test_airgap

    return test_airgap.main()


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
        print(f"{head} {detail}")
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
                h for h in block.get("hooks", []) if "pretool-phi-airgap" not in h.get("command", "")
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
    p = argparse.ArgumentParser(prog="phi-airgap", description=BANNER)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="gate, execute and scrub a .sql file")
    r.add_argument("file")
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
        help="report only, exit 1 if anything would be redacted (no output, no rewrite)",
    )
    c.set_defaults(fn=cmd_scrub)

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
