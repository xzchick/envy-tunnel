import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from envy_tunnel import keys, server
from envy_tunnel.connect import elevate, plan_down, plan_up
from envy_tunnel.manager import Manager
from envy_tunnel.model import (Server, State, TunnelError, check_host, check_name, client_config,
                               human_ago, human_bytes, parse_wg_dump)
from envy_tunnel.store import Store


class KeyTests(unittest.TestCase):
    def test_rfc7748_public_key(self):
        # RFC 7748 §6.1 (Alice).
        priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(keys.public_key(base64.b64encode(priv).decode()), base64.b64encode(pub).decode())

    def test_generated_keys_are_clamped_and_valid(self):
        for _ in range(20):
            priv = keys.generate_private_key()
            raw = base64.b64decode(priv)
            self.assertEqual(len(priv), 44)
            self.assertEqual(raw[0] & 7, 0)
            self.assertEqual(raw[31] & 0xC0, 0x40)
            self.assertTrue(keys.is_key(keys.public_key(priv)))
        self.assertNotEqual(keys.generate_preshared_key(), keys.generate_preshared_key())

    def test_rejects_bad_keys(self):
        for bad in ("", "abc", "!" * 44, base64.b64encode(b"x" * 31).decode(), None):
            self.assertFalse(keys.is_key(bad))


class ModelTests(unittest.TestCase):
    def state(self):
        st = State()
        st.server = Server(host="vpn.example.com").validate()
        return st

    def test_validation(self):
        self.assertEqual(check_host("VPN.Example.com."), "vpn.example.com")
        self.assertEqual(check_host("[2001:db8::1]"), "2001:db8::1")
        for bad in ("", "a b", "1.2.3", "-x.com", "x;rm -rf /", "$(id)"):
            with self.assertRaises(TunnelError):
                check_host(bad)
        for bad in ("", "-x", "a/b", "a b", "x" * 33, "a;b", "é"):
            with self.assertRaises(TunnelError):
                check_name(bad)
        with self.assertRaises(TunnelError):
            Server(host="h.example", ssh_user="root; id").validate()
        with self.assertRaises(TunnelError):
            Server(host="h.example", subnet4="8.8.8.0/24").validate()
        with self.assertRaises(TunnelError):
            Server(host="h.example", dns=["not-ip"]).validate()

    def test_allocation_is_lowest_free_and_reuses_gaps(self):
        st = self.state()
        pubs = [keys.public_key(keys.generate_private_key()) for _ in range(4)]
        a = st.add_device("a", pubs[0]); b = st.add_device("b", pubs[1])
        self.assertEqual((a.address4, b.address4), ("10.66.0.2", "10.66.0.3"))
        self.assertEqual(a.address6, "fd66:656e:7679::2")
        st.remove_device("a")
        c = st.add_device("c", pubs[2])
        self.assertEqual(c.address4, "10.66.0.2")
        with self.assertRaises(TunnelError):
            st.add_device("c", pubs[3])  # duplicate name
        with self.assertRaises(TunnelError):
            st.add_device("d", pubs[1])  # duplicate key

    def test_small_range_fills_up(self):
        st = State(server=Server(host="h.example", subnet4="10.9.9.0/29").validate())
        for i in range(5):  # .2 – .6
            st.add_device(f"d{i}", keys.public_key(keys.generate_private_key()))
        with self.assertRaises(TunnelError):
            st.add_device("full", keys.public_key(keys.generate_private_key()))

    def test_client_config(self):
        st = self.state()
        priv, psk = keys.generate_private_key(), keys.generate_preshared_key()
        d = st.add_device("phone", keys.public_key(priv))
        with self.assertRaises(TunnelError):
            client_config(st, d, priv, psk)  # server not set up
        st.server.public_key = keys.public_key(keys.generate_private_key())
        conf = client_config(st, d, priv, psk)
        self.assertIn(f"PrivateKey = {priv}", conf)
        self.assertIn("Address = 10.66.0.2/32, fd66:656e:7679::2/128", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertIn("Endpoint = vpn.example.com:51820", conf)
        self.assertIn("DNS = 1.1.1.1, 1.0.0.1", conf)
        split = client_config(st, d, priv, psk, full_tunnel=False)
        self.assertIn("AllowedIPs = 10.66.0.0/24, fd66:656e:7679::/64", split)
        self.assertNotIn("DNS", split)
        st.server.host = "2001:db8::7"
        self.assertIn("Endpoint = [2001:db8::7]:51820", client_config(st, d, priv, psk))

    def test_state_roundtrip(self):
        st = self.state()
        st.add_device("a", keys.public_key(keys.generate_private_key()))
        again = State.from_dict(json.loads(json.dumps(st.to_dict())))
        self.assertEqual(again.to_dict(), st.to_dict())
        with self.assertRaises(TunnelError):
            State.from_dict({"format": 99})

    def test_parse_dump_and_humanize(self):
        k1 = keys.public_key(keys.generate_private_key())
        dump = ("PRIV\tPUB\t51820\toff\n"
                f"{k1}\tPSK\t198.51.100.4:40000\t10.66.0.2/32\t1700000000\t1024\t2048\t25\n"
                "garbage line\n")
        peers = parse_wg_dump(dump)
        self.assertEqual(peers[k1]["rx_bytes"], 1024)
        self.assertEqual(peers[k1]["endpoint"], "198.51.100.4:40000")
        self.assertEqual(human_bytes(1536), "1.5 KB")
        self.assertEqual(human_ago(0), "never")
        self.assertEqual(human_ago(100, now=190), "1m ago")


class FakeServer:
    """Stands in for `ssh host bash -s`: records scripts, answers like the real script."""

    def __init__(self, fail=None):
        self.calls = []
        self.key = keys.public_key(keys.generate_private_key())
        self.fail = fail

    def __call__(self, argv, stdin, timeout):
        self.calls.append((argv, stdin))
        if self.fail:
            return self.fail
        out = "ENVY-STEP did a thing\n"
        if "ENVY-DUMP-BEGIN" in stdin:
            out += "ENVY-DUMP-BEGIN\nPRIV\tPUB\t51820\toff\nENVY-DUMP-END\n"
        return 0, out + f"ENVY-SERVER-PUBLIC-KEY {self.key}\nENVY-OK\n", ""


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = FakeServer()
        self.mgr = Manager(Store(Path(self.tmp)), runner=self.fake, log=lambda m: None)
        self.mgr.configure(host="vpn.example.com", ssh_user="ubuntu")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_flow(self):
        self.mgr.add_device("laptop")
        key = self.mgr.setup_server()
        self.assertEqual(key, self.fake.key)
        argv, script = self.fake.calls[-1]
        self.assertEqual(argv[-2:], ["ubuntu@vpn.example.com", "sudo -n bash -s"])
        self.assertIn("BatchMode=yes", argv)
        secrets = self.mgr.store.load_secrets()
        self.assertIn(secrets["laptop"]["preshared_key"], script)
        self.assertNotIn(secrets["laptop"]["private_key"], script)  # device private key never sent
        self.assertFalse(self.mgr.state.pending_sync)
        conf = self.mgr.config_for("laptop")
        self.assertIn(f"PublicKey = {self.fake.key}", conf)
        self.mgr.remove_device("laptop")
        self.assertTrue(self.mgr.state.pending_sync)
        self.assertNotIn("laptop", self.mgr.store.load_secrets())
        self.mgr.sync()
        self.assertNotIn("laptop", self.fake.calls[-1][1])
        self.assertEqual(self.mgr.status(), {})

    def test_export_never_overwrites_and_is_private(self):
        self.mgr.add_device("pc")
        self.mgr.setup_server()
        out = Path(self.tmp) / "pc.conf"
        self.mgr.export("pc", out)
        with self.assertRaises(TunnelError):
            self.mgr.export("pc", out)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.mgr.store.secrets_path.stat().st_mode), 0o600)

    def test_changing_server_forgets_old_key(self):
        self.mgr.setup_server()
        self.mgr.configure(host="other.example.com")
        self.assertEqual(self.mgr.state.server.public_key, "")

    def test_server_errors_are_readable(self):
        cases = [((3, "ENVY-ERROR needs root\n", ""), "needs root"),
                 ((255, "", "ssh: connect to host x port 22: Connection refused\n"), "Could not connect"),
                 ((1, "", "sudo: a password is required\n"), "sudo needs a password"),
                 ((1, "", "boom\n"), "exit 1")]
        for answer, expect in cases:
            self.mgr.runner = FakeServer(fail=answer)
            with self.assertRaises(TunnelError) as ctx:
                self.mgr.setup_server()
            self.assertIn(expect, str(ctx.exception))


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.st = State(server=Server(host="vpn.example.com").validate())
        priv = keys.generate_private_key()
        self.st.add_device("phone", keys.public_key(priv))
        self.psks = {"phone": keys.generate_preshared_key()}

    def test_scripts_are_valid_bash(self):
        bash = shutil.which("bash")
        if not bash or os.name == "nt":
            self.skipTest("bash not available")
        for script in (server.setup_script(self.st, self.psks), server.sync_script(self.st, self.psks),
                       server.status_script(self.st), server.uninstall_script(self.st)):
            proc = subprocess.run([bash, "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_script_content(self):
        s = server.setup_script(self.st, self.psks)
        self.assertIn("WG_IF=wg0", s)
        self.assertIn("WG_PORT=51820", s)
        self.assertIn("AllowedIPs = 10.66.0.2/32, fd66:656e:7679::2/128", s)
        self.assertIn("already configured by something other than ENVY", s)
        self.assertIn("<<'ENVY_PEERS_END'", s)  # quoted heredoc: nothing in it is expanded
        with self.assertRaises(TunnelError):
            server.sync_script(self.st, {})  # missing PSK

    def test_ssh_argv(self):
        srv = Server(host="203.0.113.9", ssh_port=2222, ssh_key="/k/id_ed25519").validate()
        argv = server.ssh_argv(srv, interactive=True)
        self.assertEqual(argv[:3], ["ssh", "-p", "2222"])
        self.assertNotIn("BatchMode=yes", argv)
        self.assertIn("/k/id_ed25519", argv)
        self.assertEqual(argv[-2:], ["root@203.0.113.9", "bash -s"])


class ConnectPlanTests(unittest.TestCase):
    conf = Path("/x/envy-tunnel.conf")

    def test_linux_prefers_networkmanager(self):
        plan = plan_up(self.conf, "linux", {"nmcli": "/usr/bin/nmcli", "wg-quick": "/usr/bin/wg-quick"})
        self.assertEqual(plan.method, "nmcli")
        self.assertFalse(plan.admin)
        self.assertEqual(plan.steps[1][-1], str(self.conf))
        self.assertEqual(plan.steps[2], ["/usr/bin/nmcli", "connection", "up", "envy-tunnel"])
        self.assertEqual(plan_down(self.conf, "linux", {"nmcli": "/usr/bin/nmcli"}).method, "nmcli")

    def test_wg_quick_fallback_needs_admin(self):
        plan = plan_up(self.conf, "linux", {"nmcli": None, "wg-quick": "/usr/bin/wg-quick"})
        self.assertEqual((plan.method, plan.admin), ("wg-quick", True))
        mac = plan_up(self.conf, "darwin", {"wg-quick": "/opt/homebrew/bin/wg-quick"})
        self.assertEqual(mac.steps[-1], ["/opt/homebrew/bin/wg-quick", "up", str(self.conf)])

    def test_windows_tunnel_service(self):
        exe = r"C:\Program Files\WireGuard\wireguard.exe"
        plan = plan_up(self.conf, "win32", {"wireguard": exe})
        self.assertEqual(plan.method, "wireguard-windows")
        self.assertEqual(plan.steps[-1], [exe, "/installtunnelservice", str(self.conf)])
        self.assertEqual(plan_down(self.conf, "win32", {"wireguard": exe}).steps[0],
                         [exe, "/uninstalltunnelservice", "envy-tunnel"])
        wrapped = elevate([exe, "/installtunnelservice", r"C:\Users\a b\envy-tunnel.conf"], "win32")
        self.assertEqual(wrapped[0], "powershell")
        self.assertIn('\'"C:\\Users\\a b\\envy-tunnel.conf"\'', wrapped[-1])

    def test_missing_tools_explain_what_to_install(self):
        for plat in ("darwin", "win32", "linux"):
            plan = plan_up(self.conf, plat, {})
            self.assertEqual(plan.method, "manual")
            self.assertTrue(plan.note)

    def test_manager_up_writes_private_config_and_runs_plan(self):
        tmp = tempfile.mkdtemp()
        try:
            mgr = Manager(Store(Path(tmp)), runner=FakeServer(), log=lambda m: None)
            mgr.configure(host="vpn.example.com")
            mgr.add_device("me")
            mgr.setup_server()
            ran = []

            class P:
                returncode, stdout, stderr = 0, "", ""

            def run(argv, **kw):
                ran.append(argv)
                return P()
            plan = mgr.up("me", run=run, platform="linux", tools={"nmcli": "nmcli"})
            self.assertEqual(plan.method, "nmcli")
            self.assertTrue(mgr.store.connect_path().exists())
            self.assertEqual(ran[-1], ["nmcli", "connection", "up", "envy-tunnel"])
            mgr.down(run=run, platform="linux", tools={"nmcli": "nmcli"})
            self.assertFalse(mgr.store.connect_path().exists())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
