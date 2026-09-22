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

    The hook reads ~/.phi-airgap/config.yml too, so the CLI and the hook now
    agree on which file is live.
    """
    if v := os.environ.get(env):
        return Path(v).expanduser()
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


def audit(**fields) -> None:
    line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}
    with (phi_airgap_dir() / "log.jsonl").open("a") as fh:
        fh.write(json.dumps(line, default=str) + "\n")


def control_hashes() -> dict[str, str]:
    """sha256 of the policy and config files — the ACL the gate enforces."""
    out = {}
    for name, path in (("policy_sha256", POLICY_FILE), ("config_sha256", CONFIG_FILE)):
        out[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
    return out


def last_audit(event: str) -> dict | None:
    """The most recent audit entry for `event`, from the tail of log.jsonl."""
    path = phi_airgap_dir() / "log.jsonl"
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
