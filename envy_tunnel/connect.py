"""Connect *this* computer through the tunnel, using the official WireGuard tools.

ENVY Tunnel doesn't ship its own VPN driver. It hands the config to whatever
WireGuard implementation the OS already trusts:

* **Linux** — NetworkManager (``nmcli``) if present, otherwise ``wg-quick``.
* **macOS** — ``wg-quick`` from ``brew install wireguard-tools``; otherwise the
  official WireGuard app (import the exported file or scan the QR code).
* **Windows** — the official WireGuard for Windows tunnel service
  (``wireguard.exe /installtunnelservice``), which needs an administrator.

The planning functions are pure — they take the platform and a ``which`` lookup
and return the exact commands — so every platform's plan is tested on every OS.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .model import LOCAL_TUNNEL, TunnelError

WINDOWS_WIREGUARD = [r"C:\Program Files\WireGuard\wireguard.exe",
                     r"C:\Program Files (x86)\WireGuard\wireguard.exe"]
MAC_WG_QUICK = ["/opt/homebrew/bin/wg-quick", "/usr/local/bin/wg-quick"]
LINUX_CONF = f"/etc/wireguard/{LOCAL_TUNNEL}.conf"


@dataclass
class Plan:
    method: str                      # nmcli | wg-quick | wireguard-windows | manual
    steps: list = field(default_factory=list)   # argv lists, run in order
    admin: bool = False              # the steps need administrator/root rights
    ignore_failure: set = field(default_factory=set)  # step indexes allowed to fail
    note: str = ""


def _platform(platform: str | None) -> str:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return "windows"
    if platform == "darwin":
        return "macos"
    return "linux"


def _find(candidates, which, exists):
    for c in candidates:
        if exists(c):
            return c
    return None


def find_tools(platform: str | None = None, which=shutil.which, exists=os.path.exists) -> dict:
    plat = _platform(platform)
    if plat == "windows":
        return {"wireguard": _find(WINDOWS_WIREGUARD, which, exists) or which("wireguard")}
    if plat == "macos":
        return {"wg-quick": which("wg-quick") or _find(MAC_WG_QUICK, which, exists)}
    return {"nmcli": which("nmcli"), "wg-quick": which("wg-quick")}


def _manual(plat: str, conf: Path) -> Plan:
    if plat == "macos":
        note = ("No WireGuard command-line tools found. Either install them with "
                "`brew install wireguard-tools`, or install the official WireGuard app from the "
                f"App Store and use Import tunnel(s) from file… on {conf}.")
    elif plat == "windows":
        note = ("WireGuard for Windows isn't installed. Get it from https://www.wireguard.com/install/ "
                f"then try again, or use Import tunnel(s) from file… on {conf}.")
    else:
        note = ("Neither NetworkManager (nmcli) nor wg-quick was found. Install your distribution's "
                "wireguard-tools package and try again.")
    return Plan(method="manual", note=note)


def plan_up(conf: Path, platform: str | None = None, tools: dict | None = None) -> Plan:
    plat = _platform(platform)
    tools = find_tools(plat) if tools is None else tools
    conf = Path(conf)
    if plat == "windows":
        exe = tools.get("wireguard")
        if not exe:
            return _manual(plat, conf)
        return Plan("wireguard-windows",
                    [[exe, "/uninstalltunnelservice", LOCAL_TUNNEL],
                     [exe, "/installtunnelservice", str(conf)]],
                    admin=True, ignore_failure={0})
    if plat == "linux" and tools.get("nmcli"):
        nm = tools["nmcli"]
        return Plan("nmcli", [[nm, "connection", "delete", LOCAL_TUNNEL],
                              [nm, "connection", "import", "type", "wireguard", "file", str(conf)],
                              [nm, "connection", "up", LOCAL_TUNNEL]], ignore_failure={0})
    if tools.get("wg-quick"):
        wq = shlex.quote(tools["wg-quick"])
        if plat == "linux":
            # Install into /etc/wireguard (the standard place; some distros confine
            # wg-quick to it) and bring it up by name, all under one admin prompt.
            script = (f"{wq} down {LOCAL_TUNNEL} >/dev/null 2>&1; "
                      f"install -m 600 -D {shlex.quote(str(conf))} {LINUX_CONF} && {wq} up {LOCAL_TUNNEL}")
        else:
            script = f"{wq} down {shlex.quote(str(conf))} >/dev/null 2>&1; {wq} up {shlex.quote(str(conf))}"
        return Plan("wg-quick", [["sh", "-c", script]], admin=True)
    return _manual(plat, conf)


def plan_down(conf: Path, platform: str | None = None, tools: dict | None = None) -> Plan:
    plat = _platform(platform)
    tools = find_tools(plat) if tools is None else tools
    conf = Path(conf)
    if plat == "windows":
        exe = tools.get("wireguard")
        if not exe:
            return _manual(plat, conf)
        return Plan("wireguard-windows", [[exe, "/uninstalltunnelservice", LOCAL_TUNNEL]], admin=True)
    if plat == "linux" and tools.get("nmcli"):
        nm = tools["nmcli"]
        return Plan("nmcli", [[nm, "connection", "down", LOCAL_TUNNEL],
                              [nm, "connection", "delete", LOCAL_TUNNEL]], ignore_failure={1})
    if tools.get("wg-quick"):
        wq = shlex.quote(tools["wg-quick"])
        if plat == "linux":
            script = f"{wq} down {LOCAL_TUNNEL}; rc=$?; rm -f {LINUX_CONF}; exit $rc"
        else:
            script = f"{wq} down {shlex.quote(str(conf))}"
        return Plan("wg-quick", [["sh", "-c", script]], admin=True)
    return _manual(plat, conf)


def is_connected(platform: str | None = None, run=subprocess.run, exists=os.path.exists) -> bool:
    """Best-effort check that the local tunnel is up (no admin rights needed)."""
    plat = _platform(platform)
    try:
        if plat == "windows":
            out = run(["sc", "query", f"WireGuardTunnel${LOCAL_TUNNEL}"],
                      capture_output=True, text=True, timeout=10).stdout
            return "RUNNING" in out
        if plat == "macos":
            return exists(f"/var/run/wireguard/{LOCAL_TUNNEL}.name")
        return exists(f"/sys/class/net/{LOCAL_TUNNEL}")
    except (OSError, subprocess.SubprocessError):
        return False


def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def elevate(argv: list[str], platform: str | None = None, gui: bool = False) -> list[str]:
    """Wrap a command so it runs with administrator rights, asking the OS the normal way."""
    plat = _platform(platform)
    if plat == "windows":
        # Each argument is double-quoted inside a PowerShell single-quoted string, so
        # paths with spaces (e.g. %APPDATA%\ENVY Tunnel) arrive as one argument.
        quoted = ",".join("'\"" + a.replace("'", "''") + "\"'" for a in argv[1:])
        return ["powershell", "-NoProfile", "-Command",
                f"$p = Start-Process -FilePath '{argv[0]}' -ArgumentList {quoted} -Verb RunAs "
                f"-Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode"]
    if plat == "macos" and gui:
        import shlex
        cmd = " ".join(shlex.quote(a) for a in argv).replace("\\", "\\\\").replace('"', '\\"')
        return ["osascript", "-e", f'do shell script "{cmd}" with administrator privileges']
    if plat == "linux" and gui and shutil.which("pkexec"):
        return ["pkexec"] + argv
    return ["sudo"] + argv


def execute(plan: Plan, gui: bool = False, run=subprocess.run, log=print,
            platform: str | None = None) -> None:
    if plan.method == "manual":
        raise TunnelError(plan.note)
    needs = plan.admin and not is_admin()
    for index, argv in enumerate(plan.steps):
        full = elevate(argv, platform, gui) if needs else argv
        log("↳ " + " ".join(full))
        try:
            proc = run(full, capture_output=True, text=True, timeout=120)
        except FileNotFoundError as exc:
            raise TunnelError(f"Command not found: {exc.filename}") from None
        if proc.returncode != 0 and index not in plan.ignore_failure:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
            raise TunnelError(f"{Path(argv[0]).name} failed (exit {proc.returncode}). " + " ".join(detail))
