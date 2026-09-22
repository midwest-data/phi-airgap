"""Paths, config, Keychain access, audit log."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
from importlib.resources import files
from pathlib import Path

import yaml

# Packaged examples + the hook, shipped inside the wheel so a `pip install`
# works without the repo checkout.
DATA = Path(str(files("phi_airgap") / "data"))
HOME_DIR = Path.home() / ".phi-airgap"


def _pick(env: str, name: str) -> Path:
    """$ENV override, else ~/.phi-airgap/<name>, else the packaged example.

    The override is honoured only when it points under ~/.phi-airgap/ or
    PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1 is set (selftest/CI). Otherwise a settings
    `env` block could point the CLI at a policy the agent wrote. The hook
    applies the same rule, so the CLI and the hook agree on which file is live.
    """
    if v := os.environ.get(env):
        p = Path(v).expanduser()
        try:
            under_home = p.resolve().is_relative_to(HOME_DIR.resolve())
        except (OSError, RuntimeError):
            under_home = False
        if under_home or os.environ.get("PHI_AIRGAP_ALLOW_ENV_OVERRIDE") == "1":
            return p
        print(
            f"phi-airgap: ignoring {env}={v} (not under {HOME_DIR}; set "
            "PHI_AIRGAP_ALLOW_ENV_OVERRIDE=1 to force)",
            file=sys.stderr,
        )
    home = HOME_DIR / name
    return home if home.exists() else DATA / f"{name.removesuffix('.yml')}.example.yml"


CONFIG_FILE = _pick("PHI_AIRGAP_CONFIG", "config.yml")
POLICY_FILE = _pick("PHI_AIRGAP_POLICY", "policy.yml")

DEFAULT_CONFIG = {
    "default_root": ".",
    "adapter": "databricks",
    "sql_dialect": "databricks",
    "keychain_service": "phi-airgap-databricks-pat",
    "keychain_github_service": "phi-airgap-github-pat",
    # An optional Keychain service the agent MAY read directly, for a credential
    # that reaches no sensitive data (e.g. an issue-tracker API key). Empty by
    # default: with nothing set, every credential read is blocked.
    "readable_keychain_service": "",
    "host": "<workspace>.cloud.databricks.com",
    "http_path": "/sql/1.0/warehouses/<id>",
    # Catalogs to pull column metadata from via information_schema. Empty by
    # default; set to your reviewed list.
    "network_catalogs": [],
    # dbt run/test/build emit logs and counts, never result rows, so the agent
    # may drive them. Flip to false for a stricter phi-airgap.
    "allow_claude_dbt": True,
    "k_threshold": 11,
    "max_rows": 5000,
    "max_rows_sensitive": 200,
    "require_presidio": True,
    "max_suppressed_share": 0.5,
    # The hook fails CLOSED on malformed input or a crash (exit 2). Flip to true
    # to fail open (the pre-1.2 behaviour).
    "hook_fail_open": False,
}


def config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        cfg.update(yaml.safe_load(CONFIG_FILE.read_text()) or {})
    return cfg


def root() -> Path:
    """Workspace root that owns the .phi-airgap directory.

    PHI_AIRGAP_ROOT wins, then the nearest ancestor already holding a .phi-airgap dir (so
    git worktrees get their own), then the configured default, then cwd.
    """
    if env := os.environ.get("PHI_AIRGAP_ROOT"):
        return Path(env).expanduser().resolve()
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if (parent / ".phi-airgap").is_dir():
            return parent
    default = Path(config()["default_root"]).expanduser()
    return default.resolve() if default.is_dir() else cwd


def phi_airgap_dir() -> Path:
    d = root() / ".phi-airgap"
    (d / "out").mkdir(parents=True, exist_ok=True)
    (d / "meta").mkdir(parents=True, exist_ok=True)
    return d


def policy() -> dict:
    if not POLICY_FILE.exists():
        die(f"No policy at {POLICY_FILE}. Run `phi-airgap refresh --draft-policy` and review it.")
    return yaml.safe_load(POLICY_FILE.read_text()) or {}


# --- Keychain ---------------------------------------------------------------
# macOS-specific: credential storage uses the `security` CLI. On other platforms
# provide the token another way (env var, adapter override) — the gate, scrubber
# and hook do not need Keychain.


def keychain_get(service: str | None = None) -> str:
    service = service or config()["keychain_service"]
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-a", getpass.getuser(), "-s", service, "-w"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        die(f"Keychain lookup failed: {e}")
    if r.returncode != 0:
        die(
            f"No Keychain entry '{service}'. Seed it with:\n"
            f'  security add-generic-password -a "$USER" -s {service} -w'
        )
    return r.stdout.strip()


def keychain_has(service: str) -> bool:
    try:
        return (
            subprocess.run(
                ["security", "find-generic-password", "-a", getpass.getuser(), "-s", service],
                capture_output=True,
                timeout=15,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


# --- Audit log --------------------------------------------------------------


def _sha(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def _last_line(path: Path) -> str:
    if not path.exists():
        return ""
    lines = path.read_text().splitlines()
    return lines[-1] if lines else ""


def home_audit_path() -> Path:
    """The per-workspace mirror of the audit log under ~/.phi-airgap/audit/.

    The workspace log is agent-adjacent; this copy sits beside the hook's own
    config and is protected by the hook. The banner baseline reads this one.
    """
    return HOME_DIR / "audit" / f"{_sha(str(root()))[:12]}.jsonl"


def _append(path: Path, fields: dict) -> None:
    """Append one hash-chained line: `prev` is sha256 of the previous raw line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_line(path)
    line = {**fields, "prev": _sha(prev) if prev else ""}
    new = not path.exists()
    with path.open("a") as fh:
        fh.write(json.dumps(line, default=str) + "\n")
    if new:
        path.chmod(0o600)


def audit(**fields) -> None:
    line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}
    _append(phi_airgap_dir() / "log.jsonl", line)
    _append(home_audit_path(), line)


def verify_chain(path: Path) -> tuple[bool, int]:
    """Walk the hash chain. Returns (ok, first bad line number) — (True, 0) if intact."""
    if not path.exists():
        return True, 0
    prev = ""
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        try:
            e = json.loads(raw)
        except ValueError:
            return False, n
        if e.get("prev", "") != (_sha(prev) if prev else ""):
            return False, n
        prev = raw
    return True, 0


def _strip_prev(raw: str) -> dict:
    try:
        e = json.loads(raw)
    except ValueError:
        return {}
    e.pop("prev", None)
    return e


def tails_match() -> bool:
    """True when the workspace log and its home mirror end on the same entry."""
    ws, home = _last_line(phi_airgap_dir() / "log.jsonl"), _last_line(home_audit_path())
    return _strip_prev(ws) == _strip_prev(home)


def control_hashes() -> dict[str, str]:
    """sha256 of the policy and config files — the ACL the gate enforces."""
    out = {}
    for name, path in (("policy_sha256", POLICY_FILE), ("config_sha256", CONFIG_FILE)):
        out[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
    return out


def last_audit(event: str, home: bool = False) -> dict | None:
    """The most recent audit entry for `event`, from the tail of the log
    (`home=True`: the ~/.phi-airgap/audit/ mirror, which the agent cannot rewrite)."""
    path = home_audit_path() if home else phi_airgap_dir() / "log.jsonl"
    if not path.exists():
        return None
    for line in reversed(path.read_text().splitlines()[-500:]):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") == event:
            return e
    return None


def die(msg: str, code: int = 2) -> None:
    print(f"phi-airgap: {msg}", file=sys.stderr)
    sys.exit(code)
