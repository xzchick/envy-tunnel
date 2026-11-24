"""Real end-to-end test: an actual WireGuard server and client on one Linux machine.

Runs in CI on a throwaway Ubuntu VM (needs root via sudo and wireguard-tools):

1. The machine itself plays the VPS. ENVY's real ``setup`` script runs as root
   (piped to ``sudo bash -s`` exactly as it would be over ssh): it installs nothing
   new, creates wg0 under systemd, enables forwarding and NAT.
2. A network namespace plays the client device, connected to the "VPS" over a
   virtual Ethernet link. It brings up the config ENVY generated with wg-quick.
3. Checks: the handshake happens, the client can reach the server through the
   tunnel, its internet traffic is NATed out through the server, ``status`` sees
   the handshake, live ``sync`` adds and revokes peers, and ``uninstall`` cleans up.

Never run this on a machine you care about: it changes networking as root.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from envy_tunnel.manager import Manager  # noqa: E402
from envy_tunnel.store import Store  # noqa: E402

NS = "envyc"


def sh(*argv, check=True, capture=False):
    print("+", " ".join(argv), flush=True)
    proc = subprocess.run(argv, text=True, capture_output=capture)
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(argv)}\n"
                         f"{proc.stdout or ''}{proc.stderr or ''}")
    return proc


def local_root(argv, stdin, timeout):
    """Stand-in for ssh: run the script as root on this machine."""
    proc = subprocess.run(["sudo", "bash", "-s"], input=stdin, capture_output=True, text=True,
                          timeout=timeout)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode, proc.stdout, proc.stderr


def in_ns(*argv, check=True, capture=False):
    return sh("sudo", "ip", "netns", "exec", NS, *argv, check=check, capture=capture)


def main():
    if not sys.platform.startswith("linux"):
        raise SystemExit("Linux only")
    work = Path(tempfile.mkdtemp())
    mgr = Manager(Store(work / "home"), runner=local_root, log=print)

    # The client "device": a namespace linked to the host over a veth pair.
    sh("sudo", "ip", "netns", "add", NS)
    sh("sudo", "ip", "link", "add", "veth-envy", "type", "veth", "peer", "name", "veth-envyc")
    sh("sudo", "ip", "link", "set", "veth-envyc", "netns", NS)
    sh("sudo", "ip", "addr", "add", "192.168.77.1/24", "dev", "veth-envy")
    sh("sudo", "ip", "link", "set", "veth-envy", "up")
    in_ns("ip", "addr", "add", "192.168.77.2/24", "dev", "veth-envyc")
    in_ns("ip", "link", "set", "veth-envyc", "up")
    in_ns("ip", "link", "set", "lo", "up")
    in_ns("ip", "route", "add", "default", "via", "192.168.77.1")

    mgr.configure(host="192.168.77.1", ssh_user="root")
    mgr.add_device("ci-client")
    key = mgr.setup_server()
    assert key, "setup did not report the server key"
    print("server key:", key)

    conf = work / "envy-tunnel.conf"
    # No DNS line: the namespace has no resolvconf; everything else is ENVY's config.
    text = "\n".join(l for l in mgr.config_for("ci-client").splitlines() if not l.startswith("DNS ="))
    conf.write_text(text + "\n")
    os.chmod(conf, 0o600)
    in_ns("wg-quick", "up", str(conf))

    in_ns("ping", "-c", "3", "-W", "3", "10.66.0.1")
    print("OK: client reaches the server through the tunnel")

    code = in_ns("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15",
                 "https://1.1.1.1/", capture=True, check=False)
    print("internet via tunnel ->", code.stdout, code.stderr)
    assert code.returncode == 0 and code.stdout.strip().startswith(("2", "3")), "NAT through server failed"
    print("OK: client's internet traffic is NATed out through the server")

    stats = mgr.status()
    assert stats["ci-client"]["latest_handshake"] > 0, stats
    assert stats["ci-client"]["rx_bytes"] > 0, stats
    print("OK: status sees the handshake", stats)

    mgr.add_device("second")
    mgr.sync()
    peers = sh("sudo", "wg", "show", "wg0", "peers", capture=True).stdout.split()
    assert len(peers) == 2, peers
    in_ns("ping", "-c", "1", "-W", "3", "10.66.0.1")  # live sync kept the first client connected
    mgr.remove_device("second")
    mgr.sync()
    peers = sh("sudo", "wg", "show", "wg0", "peers", capture=True).stdout.split()
    assert len(peers) == 1, peers
    print("OK: live sync adds and revokes devices without dropping connections")

    mgr.remove_device("ci-client")
    mgr.sync()
    lost = in_ns("ping", "-c", "2", "-W", "2", "10.66.0.1", check=False, capture=True)
    assert lost.returncode != 0, "a revoked device could still reach the server"
    print("OK: a revoked device is cut off")

    in_ns("wg-quick", "down", str(conf), check=False)
    mgr.uninstall_server()
    gone = sh("ip", "link", "show", "wg0", check=False, capture=True)
    assert gone.returncode != 0, "wg0 still present after uninstall"
    assert not Path("/etc/sysctl.d/99-envy-tunnel.conf").exists()
    print("OK: uninstall removed the server setup")
    sh("sudo", "ip", "netns", "del", NS, check=False)
    print("WireGuard end-to-end test passed")


if __name__ == "__main__":
    main()
