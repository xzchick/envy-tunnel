"""The tunnel's data model: one server you own, and the devices allowed onto it.

Everything here is pure (no files, no network) so it behaves identically on every
OS and is fully unit-tested. Values that end up in a WireGuard config or a shell
script are validated against strict patterns first.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .keys import is_key

DEFAULT_SUBNET4 = "10.66.0.0/24"
DEFAULT_SUBNET6 = "fd66:656e:7679::/64"  # a fixed unique-local range ("envy" in hex)
DEFAULT_PORT = 51820
DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]
INTERFACE = "wg0"
LOCAL_TUNNEL = "envy-tunnel"  # the connection name used on this computer

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_IFACE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")


class TunnelError(Exception):
    """A user-facing problem (bad input, missing setup, failed server step)."""


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not _NAME.match(name):
        raise TunnelError("Device names use letters, digits, '.', '_' or '-' (1–32 characters, "
                          "starting with a letter or digit).")
    return name


def check_host(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOSTNAME.match(host) or host.replace(".", "").isdigit():
        raise TunnelError(f"{host!r} is not a valid server hostname or IP address.")
    return host.rstrip(".").lower()


def check_user(user: str) -> str:
    user = (user or "").strip()
    if not _USER.match(user):
        raise TunnelError(f"{user!r} is not a valid SSH user name.")
    return user


def check_port(port) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError):
        raise TunnelError(f"{port!r} is not a port number.") from None
    if not 1 <= value <= 65535:
        raise TunnelError("Ports are 1–65535.")
    return value


def check_dns(servers) -> list[str]:
    out = []
    for item in servers:
        try:
            out.append(str(ipaddress.ip_address(str(item).strip())))
        except ValueError:
            raise TunnelError(f"{item!r} is not a DNS server IP address.") from None
    return out


def check_interface(name: str) -> str:
    if not _IFACE.match(name or ""):
        raise TunnelError("Interface names are 1–15 characters of letters, digits or _=+.-")
    return name


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Server:
    host: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: str = ""            # optional path to an SSH identity file
    wg_port: int = DEFAULT_PORT
    interface: str = INTERFACE
    subnet4: str = DEFAULT_SUBNET4
    subnet6: str = DEFAULT_SUBNET6
    dns: list = field(default_factory=lambda: list(DEFAULT_DNS))
    public_key: str = ""         # learned from the server after setup

    def validate(self) -> "Server":
        self.host = check_host(self.host)
        self.ssh_user = check_user(self.ssh_user)
        self.ssh_port = check_port(self.ssh_port)
        self.wg_port = check_port(self.wg_port)
        self.interface = check_interface(self.interface)
        self.dns = check_dns(self.dns)
        net4 = ipaddress.ip_network(self.subnet4, strict=True)
        net6 = ipaddress.ip_network(self.subnet6, strict=True)
        if net4.version != 4 or not net4.is_private or net4.prefixlen > 29:
            raise TunnelError("The IPv4 tunnel range must be a private /29 or larger.")
        if net6.version != 6 or not net6.is_private or net6.prefixlen > 120:
            raise TunnelError("The IPv6 tunnel range must be a private (fd00::/8) /120 or larger.")
        if self.public_key and not is_key(self.public_key):
            raise TunnelError("The stored server public key is not a valid WireGuard key.")
        return self

    @property
    def endpoint(self) -> str:
        host = self.host
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        return f"{host}:{self.wg_port}"

    def gateway4(self) -> ipaddress.IPv4Interface:
        net = ipaddress.ip_network(self.subnet4)
        return ipaddress.ip_interface(f"{net.network_address + 1}/{net.prefixlen}")

    def gateway6(self) -> ipaddress.IPv6Interface:
        net = ipaddress.ip_network(self.subnet6)
        return ipaddress.ip_interface(f"{net.network_address + 1}/{net.prefixlen}")


@dataclass
class Device:
    name: str
    address4: str
    address6: str
    public_key: str
    created: str = field(default_factory=_now)


@dataclass
class State:
    server: Server = field(default_factory=Server)
    devices: list = field(default_factory=list)
    pending_sync: bool = False   # devices changed locally but not yet pushed to the server

    def to_dict(self) -> dict:
        return {"format": 1, "server": asdict(self.server),
                "devices": [asdict(d) for d in self.devices], "pending_sync": self.pending_sync}

    @classmethod
    def from_dict(cls, data: dict) -> "State":
        if data.get("format") != 1:
            raise TunnelError("Unrecognised tunnel state file format.")
        known = Server.__dataclass_fields__
        server = Server(**{k: v for k, v in (data.get("server") or {}).items() if k in known})
        devices = [Device(**d) for d in data.get("devices", [])]
        return cls(server=server, devices=devices, pending_sync=bool(data.get("pending_sync")))

    def device(self, name: str) -> Device:
        for d in self.devices:
            if d.name == name:
                return d
        raise TunnelError(f"No device named {name!r}.")

    def allocate(self) -> tuple[str, str]:
        """The lowest free host address in each range (.1 is the server)."""
        net4 = ipaddress.ip_network(self.server.subnet4)
        net6 = ipaddress.ip_network(self.server.subnet6)
        used = {d.address4 for d in self.devices}
        for offset in range(2, net4.num_addresses - 1):
            candidate = str(net4.network_address + offset)
            if candidate not in used:
                return candidate, str(net6.network_address + offset)
        raise TunnelError(f"The tunnel range {net4} is full.")

    def add_device(self, name: str, public_key: str) -> Device:
        name = check_name(name)
        if any(d.name == name for d in self.devices):
            raise TunnelError(f"A device named {name!r} already exists.")
        if not is_key(public_key):
            raise TunnelError("Not a valid WireGuard public key.")
        if any(d.public_key == public_key for d in self.devices):
            raise TunnelError("That public key is already in use by another device.")
        a4, a6 = self.allocate()
        device = Device(name=name, address4=a4, address6=a6, public_key=public_key)
        self.devices.append(device)
        self.pending_sync = True
        return device

    def remove_device(self, name: str) -> Device:
        device = self.device(name)
        self.devices.remove(device)
        self.pending_sync = True
        return device


def client_config(state: State, device: Device, private_key: str, preshared_key: str,
                  full_tunnel: bool = True) -> str:
    """The wg-quick config for one device (works in every official WireGuard app)."""
    server = state.server
    if not server.public_key:
        raise TunnelError("The server isn't set up yet, so there's no server key to connect to.")
    allowed = "0.0.0.0/0, ::/0" if full_tunnel else f"{server.subnet4}, {server.subnet6}"
    lines = ["[Interface]",
             f"# ENVY Tunnel device: {device.name}",
             f"PrivateKey = {private_key}",
             f"Address = {device.address4}/32, {device.address6}/128"]
    if full_tunnel and server.dns:
        lines.append("DNS = " + ", ".join(server.dns))
    lines += ["", "[Peer]",
              f"PublicKey = {server.public_key}",
              f"PresharedKey = {preshared_key}",
              f"Endpoint = {server.endpoint}",
              f"AllowedIPs = {allowed}",
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def server_peers_block(state: State, preshared: dict) -> str:
    """The [Peer] sections the server needs, one per device."""
    chunks = []
    for d in state.devices:
        psk = preshared.get(d.name)
        if not psk or not is_key(psk):
            raise TunnelError(f"The preshared key for {d.name!r} is missing from this computer.")
        chunks.append("\n".join([f"# envy-device: {d.name}", "[Peer]",
                                 f"PublicKey = {d.public_key}", f"PresharedKey = {psk}",
                                 f"AllowedIPs = {d.address4}/32, {d.address6}/128", ""]))
    return "\n".join(chunks)


def parse_wg_dump(text: str) -> dict:
    """Parse ``wg show <if> dump`` into {public_key: {handshake, rx, tx, endpoint}}."""
    peers = {}
    for line in text.splitlines()[1:]:  # first line is the interface itself
        parts = line.split("\t")
        if len(parts) < 8 or not is_key(parts[0]):
            continue
        handshake = int(parts[4]) if parts[4].isdigit() else 0
        peers[parts[0]] = {
            "endpoint": "" if parts[2] == "(none)" else parts[2],
            "latest_handshake": handshake,
            "rx_bytes": int(parts[5]) if parts[5].isdigit() else 0,
            "tx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
        }
    return peers


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def human_ago(epoch: int, now: float | None = None) -> str:
    if not epoch:
        return "never"
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    seconds = max(0, int(now - epoch))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"
