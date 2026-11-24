"""Command-line entry point. With no arguments the app window opens."""

from __future__ import annotations

import argparse
import sys

from . import __version__, qr
from .connect import is_connected
from .manager import Manager
from .model import TunnelError, human_ago, human_bytes

SCRIPT_WARNING = ("# Note: this script contains the devices' preshared keys. Paste it only into "
                  "your own server's console, and don't share it.\n")


def _err(*parts) -> None:
    print(*parts, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="envy-tunnel",
        description="Your own WireGuard VPN on a server you control. Run with no arguments "
                    "to open the app window.")
    root.add_argument("--version", action="version", version=f"envy-tunnel {__version__}")
    root.add_argument("--interactive", action="store_true",
                      help="let ssh ask for passwords/passphrases (default: keys/agent only)")
    sub = root.add_subparsers(dest="command")
    sub.add_parser("gui", help="open the app window (default)")

    p = sub.add_parser("init", help="set (or change) the server this tunnel uses")
    p.add_argument("--host", required=True, help="the server's public hostname or IP address")
    p.add_argument("--user", default=None, help="SSH user (default root; others need passwordless sudo)")
    p.add_argument("--ssh-port", type=int, default=None)
    p.add_argument("--ssh-key", default=None, help="SSH identity file (default: your ssh config/agent)")
    p.add_argument("--wg-port", type=int, default=None, help="WireGuard UDP port (default 51820)")
    p.add_argument("--dns", nargs="+", default=None, help="DNS servers for connected devices")

    p = sub.add_parser("setup", help="install and start WireGuard on the server over SSH")
    p.add_argument("--print", action="store_true", help="print the script instead of running it")
    p = sub.add_parser("sync", help="push this computer's device list to the server")
    p.add_argument("--print", action="store_true", help="print the script instead of running it")
    sub.add_parser("status", help="show each device's last handshake and traffic (over SSH)")
    p = sub.add_parser("uninstall-server", help="remove ENVY's WireGuard setup from the server")
    p.add_argument("--print", action="store_true", help="print the script instead of running it")
    p = sub.add_parser("set-server-key", help="record the server key printed by a script you ran yourself")
    p.add_argument("key")

    p = sub.add_parser("add", help="create a device (keys are made on this computer)")
    p.add_argument("name")
    p.add_argument("--no-sync", action="store_true", help="don't contact the server yet")
    p.add_argument("--qr", action="store_true", help="print a QR code to scan with the phone app")
    p = sub.add_parser("remove", help="revoke a device")
    p.add_argument("name")
    p.add_argument("--no-sync", action="store_true", help="don't contact the server yet")
    sub.add_parser("list", help="list devices (offline)")
    p = sub.add_parser("show", help="print a device's WireGuard config (offline)")
    p.add_argument("name")
    p.add_argument("--qr", action="store_true", help="show it as a QR code instead")
    p.add_argument("--split", action="store_true", help="only route tunnel addresses, not all traffic")
    p = sub.add_parser("export", help="save a device's config (.conf) or QR code (.png/.svg)")
    p.add_argument("name")
    p.add_argument("path")
    p.add_argument("--split", action="store_true", help="only route tunnel addresses, not all traffic")

    p = sub.add_parser("up", help="connect this computer as the given device")
    p.add_argument("name")
    sub.add_parser("down", help="disconnect this computer")
    sub.add_parser("connected", help="exit 0 if this computer's tunnel is up, 1 if not")
    return root


def _print_script(mgr: Manager, kind: str) -> int:
    sys.stdout.write(SCRIPT_WARNING if kind in ("setup", "sync") else "")
    sys.stdout.write(mgr.script(kind))
    if kind == "setup":
        _err("Run it on the server as root, then record the key it prints with:\n"
             "  envy-tunnel set-server-key <key>")
    return 0


def _sync_after(mgr: Manager, skip: bool) -> None:
    if skip or not mgr.state.server.public_key:
        _err("Not pushed to the server yet. Run `envy-tunnel sync` (or `setup`) when ready.")
        return
    mgr.sync()
    print("Server updated.")


def run(args: argparse.Namespace) -> int:
    mgr = Manager(log=lambda m: _err(m), interactive=args.interactive)
    cmd = args.command
    if cmd == "init":
        fields = {"host": args.host, "ssh_user": args.user, "ssh_port": args.ssh_port,
                  "ssh_key": args.ssh_key, "wg_port": args.wg_port, "dns": args.dns}
        mgr.configure(**fields)
        s = mgr.state.server
        print(f"Server set to {s.ssh_user}@{s.host} (SSH port {s.ssh_port}); WireGuard on UDP {s.wg_port}.")
        print("Next: envy-tunnel setup")
        return 0
    if not mgr.state.server.host and cmd not in ("list", "connected", "down"):
        raise TunnelError("No server yet. Start with: envy-tunnel init --host <your server>")
    if cmd in ("setup", "sync", "uninstall-server"):
        kind = "uninstall" if cmd == "uninstall-server" else cmd
        if args.print:
            return _print_script(mgr, kind)
        if kind == "setup":
            key = mgr.setup_server()
            print(f"Server ready. Server key: {key}")
            print(f"{len(mgr.state.devices)} device(s) loaded. Add one with: envy-tunnel add <name>")
        elif kind == "sync":
            mgr.sync()
            print(f"Server updated: {len(mgr.state.devices)} device(s).")
        else:
            mgr.uninstall_server()
            print("ENVY's WireGuard setup was removed from the server.")
        return 0
    if cmd == "set-server-key":
        mgr.set_server_key(args.key)
        print("Server key recorded.")
        return 0
    if cmd == "status":
        stats = mgr.status()
        if not stats:
            print("No devices yet.")
        for d in mgr.state.devices:
            st = stats[d.name]
            print(f"{d.name:<20} {d.address4:<15} handshake {human_ago(st['latest_handshake']):<10} "
                  f"↓ {human_bytes(st['rx_bytes']):<9} ↑ {human_bytes(st['tx_bytes'])}")
        return 0
    if cmd == "add":
        device = mgr.add_device(args.name)
        print(f"Added {device.name} at {device.address4} / {device.address6}.")
        _sync_after(mgr, args.no_sync)
        if args.qr and mgr.state.server.public_key:
            print(qr.terminal_text(mgr.config_for(device.name)))
        return 0
    if cmd == "remove":
        device = mgr.remove_device(args.name)
        print(f"Removed {device.name}; its keys were deleted from this computer.")
        _sync_after(mgr, args.no_sync)
        return 0
    if cmd == "list":
        if not mgr.state.devices:
            print("No devices yet. Add one with: envy-tunnel add <name>")
        for d in mgr.state.devices:
            print(f"{d.name:<20} {d.address4:<15} {d.address6:<28} added {d.created[:10]}")
        if mgr.state.pending_sync:
            _err("Changes not yet on the server: run `envy-tunnel sync`.")
        return 0
    if cmd == "show":
        config = mgr.config_for(args.name, full_tunnel=not args.split)
        print(qr.terminal_text(config) if args.qr else config, end="" if not args.qr else "\n")
        return 0
    if cmd == "export":
        config = mgr.config_for(args.name, full_tunnel=not args.split)
        lower = args.path.lower()
        if lower.endswith((".png", ".svg")):
            from pathlib import Path
            if Path(args.path).exists():
                raise TunnelError(f"{args.path} already exists; ENVY never overwrites files.")
            qr.save(config, args.path)
        else:
            mgr.export(args.name, args.path, full_tunnel=not args.split)
        print(f"Wrote {args.path}. It contains the device's private key; keep it private.")
        return 0
    if cmd == "up":
        plan = mgr.up(args.name)
        print(f"Connected as {args.name} (via {plan.method}).")
        return 0
    if cmd == "down":
        mgr.down()
        print("Disconnected.")
        return 0
    if cmd == "connected":
        up = is_connected()
        print("connected" if up else "not connected")
        return 0 if up else 1
    raise TunnelError(f"Unknown command {cmd!r}.")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "gui"):
        from .gui import launch
        return launch()
    try:
        return run(args)
    except TunnelError as exc:
        _err(f"envy-tunnel: {exc}")
        return 1
    except KeyboardInterrupt:
        _err("envy-tunnel: interrupted")
        return 130
