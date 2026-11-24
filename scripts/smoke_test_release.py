"""Run the freshly built standalone binary through a real offline workflow.

No display or network needed: it checks ``--version``, then (in a throwaway data
folder) sets a server, adds a device — which exercises the bundled
``cryptography`` — prints the setup script, records a server key, and renders the
device's config and QR code (bundled ``segno``).
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
APP = "envy-tunnel"
SERVER_KEY = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="


def main():
    binary = ROOT / "dist" / "standalone" / APP / (APP + (".exe" if os.name == "nt" else ""))
    if not binary.exists():
        raise SystemExit(f"standalone binary not found: {binary}")
    with tempfile.TemporaryDirectory() as home:
        env = dict(os.environ, ENVY_TUNNEL_HOME=home, PYTHONIOENCODING="utf-8")

        def run(*args):
            proc = subprocess.run([str(binary), *args], capture_output=True, text=True,
                                  encoding="utf-8", timeout=120, env=env)
            out = proc.stdout + proc.stderr
            if proc.returncode != 0:
                raise SystemExit(f"{' '.join(args)} failed ({proc.returncode}):\n{out}")
            return out

        version = run("--version")
        if APP not in version or not re.search(r"\d+\.\d+\.\d+", version):
            raise SystemExit(f"unexpected --version output: {version!r}")
        print(version.strip())
        run("init", "--host", "vpn.example.com")
        assert "10.66.0.2" in run("add", "smoke", "--no-sync")
        assert "ENVY_PEERS_END" in run("setup", "--print")
        run("set-server-key", SERVER_KEY)
        conf = run("show", "smoke")
        assert f"PublicKey = {SERVER_KEY}" in conf and "Endpoint = vpn.example.com:51820" in conf
        qr_png = Path(home) / "smoke.png"
        run("export", "smoke", str(qr_png))
        assert qr_png.read_bytes()[:4] == b"\x89PNG"
    print("standalone smoke test passed")


if __name__ == "__main__":
    main()
