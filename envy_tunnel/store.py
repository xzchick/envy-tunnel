"""Where ENVY Tunnel keeps its files on this computer.

* ``state.json``   — the server settings and the device list (public data only).
* ``secrets.json`` — device private keys and preshared keys. Owner-only (0600) on
  macOS/Linux; on Windows it lives in the per-user profile, whose ACL already
  excludes other users.
* ``connect/``     — the config handed to WireGuard when this computer connects.

Set ``ENVY_TUNNEL_HOME`` to keep everything somewhere else (tests use this).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from .model import LOCAL_TUNNEL, State, TunnelError


def data_dir() -> Path:
    override = os.environ.get("ENVY_TUNNEL_HOME")
    if override:
        return Path(override)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ENVY Tunnel"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "ENVY Tunnel"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "envy-tunnel"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def write_private(path: Path, text: str) -> Path:
    """Atomically write a file only the current user can read."""
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


class Store:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else data_dir()

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def secrets_path(self) -> Path:
        return self.root / "secrets.json"

    def connect_path(self) -> Path:
        # WireGuard names the interface/service after the file, so the name is fixed.
        return self.root / "connect" / f"{LOCAL_TUNNEL}.conf"

    def load(self) -> State:
        if not self.state_path.exists():
            return State()
        try:
            return State.from_dict(json.loads(self.state_path.read_text(encoding="utf-8")))
        except (ValueError, TypeError) as exc:
            raise TunnelError(f"Can't read {self.state_path}: {exc}") from exc

    def save(self, state: State) -> None:
        write_private(self.state_path, json.dumps(state.to_dict(), indent=2) + "\n")

    def load_secrets(self) -> dict:
        if not self.secrets_path.exists():
            return {}
        try:
            data = json.loads(self.secrets_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise TunnelError(f"Can't read {self.secrets_path}: {exc}") from exc
        return data if isinstance(data, dict) else {}

    def save_secrets(self, secrets: dict) -> None:
        write_private(self.secrets_path, json.dumps(secrets, indent=2) + "\n")
