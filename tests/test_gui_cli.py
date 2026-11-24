import contextlib
import io
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from envy_tunnel import cli  # noqa: E402
from envy_tunnel.manager import Manager  # noqa: E402
from envy_tunnel.store import Store  # noqa: E402
from test_core import FakeServer  # noqa: E402


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["ENVY_TUNNEL_HOME"] = self.tmp

    def tearDown(self):
        os.environ.pop("ENVY_TUNNEL_HOME", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_offline_flow(self):
        code, _, err = self.call("list")
        self.assertEqual(code, 0)
        code, _, err = self.call("add", "phone")
        self.assertEqual(code, 1)
        self.assertIn("No server yet", err)
        self.assertEqual(self.call("init", "--host", "vpn.example.com", "--user", "ubuntu")[0], 0)
        code, out, err = self.call("add", "phone", "--no-sync")
        self.assertEqual(code, 0)
        self.assertIn("10.66.0.2", out)
        self.assertIn("Not pushed", err)
        code, out, _ = self.call("list")
        self.assertIn("phone", out)
        code, out, _ = self.call("setup", "--print")
        self.assertEqual(code, 0)
        self.assertIn("preshared keys", out)
        self.assertIn("#!/usr/bin/env bash", out)
        code, _, err = self.call("show", "phone")
        self.assertEqual(code, 1)
        self.assertIn("isn't set up", err)
        key = FakeServer().key
        self.assertEqual(self.call("set-server-key", key)[0], 0)
        code, out, _ = self.call("show", "phone")
        self.assertIn(f"PublicKey = {key}", out)
        code, out, _ = self.call("show", "phone", "--qr")
        self.assertEqual(code, 0)
        self.assertGreater(len(out.splitlines()), 20)
        dest = Path(self.tmp) / "phone.png"
        self.assertEqual(self.call("export", "phone", str(dest))[0], 0)
        self.assertEqual(dest.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(self.call("export", "phone", str(dest))[0], 1)  # never overwrites
        self.assertEqual(self.call("set-server-key", "nope")[0], 1)
        self.assertEqual(self.call("remove", "phone", "--no-sync")[0], 0)
        self.assertEqual(self.call("init", "--host", "bad host")[0], 1)

    def test_version(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--version"])


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt6.QtWidgets import QApplication
        from envy_tunnel.gui import _build
        cls.app = QApplication.instance() or QApplication([])
        _, cls.Window = _build()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = FakeServer()
        self.mgr = Manager(Store(Path(self.tmp)), runner=self.fake, log=lambda m: None)
        self.win = self.Window(self.mgr)
        self.win._confirm = lambda *a: True

    def tearDown(self):
        self.win.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def wait(self):
        deadline = time.time() + 10
        while self.win.worker is not None and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.app.processEvents()
        self.assertIsNone(self.win.worker)

    def test_setup_add_qr_export_remove(self):
        self.assertIn("Enter your server", self.win.server_state.text())
        self.win.host.setText("bad host!")
        self.win.setup_server()
        self.assertIn("not a valid", self.win.status.text())
        self.win.host.setText("vpn.example.com")
        self.win.new_name.setText("laptop")
        self.win.add_device()
        self.assertIn("Set up the server", self.win.status.text())
        self.win.setup_server()
        self.wait()
        self.assertIn("Server ready", self.win.status.text())
        self.assertIn("Ready", self.win.server_state.text())
        self.assertEqual(self.win.table.rowCount(), 1)

        self.win.new_name.setText("phone")
        self.win.add_device()
        self.wait()
        self.assertIn("phone added", self.win.status.text())
        self.assertIn("AllowedIPs = 10.66.0.3/32", self.fake.calls[-1][1])
        self.assertEqual(self.win.selected(), "phone")

        dialog = self.win.make_qr_dialog("phone")
        self.assertFalse(dialog.image.pixmap().isNull())
        dialog.close()

        out = str(Path(self.tmp) / "phone.conf")
        self.win._ask_save_path = lambda s: out
        self.win.export_conf()
        self.assertIn("Saved", self.win.status.text())
        self.win.export_conf()
        self.assertIn("never overwrites", self.win.status.text())

        self.win.refresh_status()
        self.wait()
        self.assertEqual(self.win.table.item(0, 2).text(), "never")

        self.win.remove_device()
        self.wait()
        self.assertIn("phone revoked", self.win.status.text())
        self.assertEqual(self.win.table.rowCount(), 1)

    def test_errors_show_in_status(self):
        self.win.host.setText("vpn.example.com")
        self.mgr.runner = FakeServer(fail=(255, "", "Permission denied (publickey).\n"))
        self.win.setup_server()
        self.wait()
        self.assertIn("Could not connect", self.win.status.text())
        self.win.new_name.setText("bad name!")
        self.win.add_device()
        self.assertIn("Device names", self.win.status.text())
        self.win.table.clearSelection()
        self.win.show_qr()
        self.assertIn("Select a device", self.win.status.text())


if __name__ == "__main__":
    unittest.main()
