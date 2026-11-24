"""The ENVY Tunnel window: a native PyQt6 app on macOS, Windows and Linux.

Set up your server, add and revoke devices, show QR codes for phones, and connect
this computer, with every command ENVY runs shown in the log at the bottom.
"""

from __future__ import annotations

import math
import os
import sys

from . import __version__, qr
from .connect import is_connected
from .manager import Manager
from .model import TunnelError, human_ago, human_bytes
from .keys import fingerprint

BG = "#050713"
PANEL = "#0a0e22"
PANEL_HI = "#121735"
INK = "#f2f4ff"
MUTED = "#b9c3df"
DIM = "#6f7898"
PINK = "#ff3db4"
CYAN = "#35e8ff"
LAVENDER = "#ac8cff"
VIOLET = "#8547e8"
AMBER = "#ffb347"
GREEN = "#49e3a6"
LINE = "#1f2547"

COLUMNS = ["Device", "Address", "Last handshake", "Received", "Sent"]


def _build():
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRectF, QPointF
    from PyQt6.QtGui import QColor, QPainter, QLinearGradient, QRadialGradient, QFont, QPen, QBrush, QPixmap
    from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                                 QHBoxLayout, QGridLayout, QFileDialog, QFrame, QTableWidget,
                                 QTableWidgetItem, QHeaderView, QAbstractItemView, QPlainTextEdit,
                                 QDialog, QMessageBox, QSpinBox)

    class Header(QWidget):
        def __init__(self):
            super().__init__()
            self.setFixedHeight(150)
            self.phase = 0.0
            self.stars = [(((i * 139 + 37) % 1000) / 1000.0, ((i * 83 + 19) % 150) / 150.0,
                           0.6 + (i % 3) * 0.5, (i % 7) / 7.0) for i in range(56)]

        def tick(self, phase):
            self.phase = phase
            self.update()

        def paintEvent(self, _event):
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            w, h = self.width(), self.height()
            p.fillRect(self.rect(), QColor(BG))
            for cx, cy, rad, col, a in ((w - 120, 60, 240, CYAN, 70), (60, h, 280, PINK, 50),
                                        (w * 0.5, -40, 240, VIOLET, 45)):
                g = QRadialGradient(cx, cy, rad)
                c = QColor(col); c.setAlpha(a); g.setColorAt(0, c)
                c2 = QColor(col); c2.setAlpha(0); g.setColorAt(1, c2)
                p.setBrush(QBrush(g)); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(cx, cy), rad, rad)
            for sx, sy, sr, ph in self.stars:
                tw = 0.5 + 0.5 * math.sin(self.phase / 0.5 + ph * 6.28)
                c = QColor(205, 217, 255); c.setAlphaF(0.15 + 0.6 * tw)
                p.setBrush(c); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(sx * w, sy * h), sr, sr)
            pulse = 0.5 + 0.5 * math.sin(self.phase)
            font = QFont("Helvetica", 38, QFont.Weight.Bold)
            p.setFont(font)
            grad = QLinearGradient(28, 0, 360, 0)
            grad.setColorAt(0, QColor(CYAN)); grad.setColorAt(1, QColor(PINK))
            glow = QColor(CYAN); glow.setAlpha(int(60 + 60 * pulse))
            p.setPen(QPen(glow, 1))
            for dx, dy in ((1.4, 1.4), (-1.4, 1.4)):
                p.drawText(QRectF(28 + dx, 26 + dy, 460, 52), Qt.AlignmentFlag.AlignVCenter, "ENVY TUNNEL")
            p.setPen(QPen(QBrush(grad), 1))
            p.drawText(QRectF(28, 26, 460, 52), Qt.AlignmentFlag.AlignVCenter, "ENVY TUNNEL")
            p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
            p.setPen(QColor(LAVENDER))
            p.drawText(QRectF(32, 84, 600, 20), Qt.AlignmentFlag.AlignVCenter,
                       "WIREGUARD  ·  YOUR SERVER  ·  YOUR KEYS")
            # A packet travelling through the tunnel.
            y = 120
            p.setPen(QPen(QColor(LINE), 2)); p.drawLine(32, y, w - 32, y)
            span = (w - 32) - 32
            x = 32 + span * ((self.phase * 0.12) % 1.0)
            halo = QRadialGradient(x, y, 16)
            hc = QColor(PINK); hc.setAlpha(170); halo.setColorAt(0, hc)
            hc2 = QColor(PINK); hc2.setAlpha(0); halo.setColorAt(1, hc2)
            p.setBrush(QBrush(halo)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 16, 16)
            p.setBrush(QColor("#ffffff")); p.drawEllipse(QPointF(x, y), 2.5, 2.5)
            p.end()

    class Worker(QThread):
        done = pyqtSignal(str, object)
        line = pyqtSignal(str)

        def __init__(self, fn):
            super().__init__()
            self.fn = fn

        def run(self):
            try:
                self.done.emit("ok", self.fn())
            except TunnelError as exc:
                self.done.emit("error", str(exc))
            except Exception as exc:  # pragma: no cover
                self.done.emit("error", f"Unexpected error: {exc}")

    class QrDialog(QDialog):
        def __init__(self, parent, name, config):
            super().__init__(parent)
            self.setWindowTitle(f"{name} — scan with the WireGuard app")
            self.config = config
            lay = QVBoxLayout(self)
            pix = QPixmap(); pix.loadFromData(qr.png_bytes(config))
            self.image = QLabel(); self.image.setPixmap(pix)
            self.image.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.image.setAccessibleName(f"QR code for {name}")
            lay.addWidget(self.image)
            warn = QLabel("In the WireGuard app: + → Create from QR code.\n"
                          "This code contains the device's private key. Don't photograph or share it.")
            warn.setObjectName("hint"); warn.setWordWrap(True)
            lay.addWidget(warn)
            close = QPushButton("Done"); close.setObjectName("pick"); close.clicked.connect(self.accept)
            lay.addWidget(close)

    class TunnelWindow(QWidget):
        def __init__(self, manager: Manager | None = None):
            super().__init__()
            self.mgr = manager or Manager()
            self.worker = None
            self.stats = {}
            self.setWindowTitle("ENVY Tunnel")
            self.resize(920, 960)
            self.setMinimumSize(780, 860)
            self.setStyleSheet(STYLE)

            root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
            self.header = Header(); root.addWidget(self.header)
            body = QWidget(); body.setObjectName("body")
            bl = QVBoxLayout(body); bl.setContentsMargins(24, 16, 24, 18); bl.setSpacing(12)
            root.addWidget(body, 1)

            # --- server card ---
            card = QFrame(); card.setObjectName("card")
            grid = QGridLayout(card); grid.setContentsMargins(18, 14, 18, 14)
            grid.setHorizontalSpacing(10); grid.setVerticalSpacing(6)
            s = self.mgr.state.server
            self.host = QLineEdit(s.host); self.host.setPlaceholderText("vpn.example.com or 203.0.113.7")
            self.user = QLineEdit(s.ssh_user)
            self.ssh_port = QSpinBox(); self.ssh_port.setRange(1, 65535); self.ssh_port.setValue(s.ssh_port)
            self.wg_port = QSpinBox(); self.wg_port.setRange(1, 65535); self.wg_port.setValue(s.wg_port)
            self.key = QLineEdit(s.ssh_key); self.key.setPlaceholderText("Default: your ssh config / agent")
            for widget, label in ((self.host, "Server host"), (self.user, "SSH user"),
                                  (self.ssh_port, "SSH port"), (self.wg_port, "WireGuard UDP port"),
                                  (self.key, "SSH key file")):
                widget.setAccessibleName(label)
            grid.addWidget(self._tag("SERVER  ·  A LINUX VPS YOU CONTROL"), 0, 0, 1, 4)
            grid.addWidget(self.host, 1, 0, 1, 2)
            grid.addWidget(self._tag("SSH USER"), 2, 0); grid.addWidget(self._tag("SSH PORT"), 2, 1)
            grid.addWidget(self._tag("WIREGUARD PORT"), 2, 2)
            grid.addWidget(self.user, 3, 0); grid.addWidget(self.ssh_port, 3, 1); grid.addWidget(self.wg_port, 3, 2)
            grid.addWidget(self._tag("SSH KEY  ·  OPTIONAL"), 4, 0, 1, 3)
            grid.addWidget(self.key, 5, 0, 1, 3); grid.addWidget(self._btn("Key…", self.pick_key), 5, 3)
            row = QHBoxLayout(); row.setSpacing(8)
            self.b_setup = self._btn("Set up server", self.setup_server, "go")
            self.b_script = self._btn("Copy setup script", self.copy_script)
            self.b_refresh = self._btn("Refresh status", self.refresh_status)
            for b in (self.b_setup, self.b_script, self.b_refresh):
                row.addWidget(b)
            row.addStretch(1)
            grid.addLayout(row, 6, 0, 1, 4)
            self.server_state = QLabel(); self.server_state.setObjectName("hint"); self.server_state.setWordWrap(True)
            grid.addWidget(self.server_state, 7, 0, 1, 4)
            grid.setColumnStretch(0, 2); grid.setColumnStretch(1, 1); grid.setColumnStretch(2, 1)
            bl.addWidget(card)

            # --- devices card ---
            dcard = QFrame(); dcard.setObjectName("card")
            dl = QVBoxLayout(dcard); dl.setContentsMargins(18, 14, 18, 14); dl.setSpacing(8)
            dl.addWidget(self._tag("DEVICES  ·  KEYS ARE MADE ON THIS COMPUTER"))
            add = QHBoxLayout(); add.setSpacing(8)
            self.new_name = QLineEdit(); self.new_name.setPlaceholderText("New device name, e.g. phone or laptop")
            self.new_name.setAccessibleName("New device name")
            self.new_name.returnPressed.connect(self.add_device)
            self.b_add = self._btn("Add device", self.add_device, "go")
            add.addWidget(self.new_name, 1); add.addWidget(self.b_add)
            dl.addLayout(add)
            self.table = QTableWidget(0, len(COLUMNS))
            self.table.setHorizontalHeaderLabels(COLUMNS)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.setAccessibleName("Devices")
            self.table.setMinimumHeight(170)
            self.table.verticalHeader().setDefaultSectionSize(30)
            dl.addWidget(self.table, 1)
            acts = QHBoxLayout(); acts.setSpacing(8)
            self.b_qr = self._btn("QR code", self.show_qr)
            self.b_export = self._btn("Export .conf…", self.export_conf)
            self.b_remove = self._btn("Remove", self.remove_device)
            self.b_up = self._btn("Connect this computer", self.connect_up, "go")
            self.b_down = self._btn("Disconnect", self.connect_down)
            for b in (self.b_qr, self.b_export, self.b_remove):
                acts.addWidget(b)
            acts.addStretch(1)
            acts.addWidget(self.b_up); acts.addWidget(self.b_down)
            dl.addLayout(acts)
            self.conn = QLabel(); self.conn.setObjectName("conn")
            dl.addWidget(self.conn)
            bl.addWidget(dcard, 2)

            # --- log ---
            bl.addWidget(self._tag("EVERY COMMAND ENVY RUNS"))
            self.log = QPlainTextEdit(); self.log.setReadOnly(True); self.log.setObjectName("log")
            self.log.setMaximumBlockCount(500); self.log.setFixedHeight(96)
            self.log.setAccessibleName("Command log")
            bl.addWidget(self.log)
            self.status = QLabel("Ready."); self.status.setObjectName("status"); self.status.setWordWrap(True)
            bl.addWidget(self.status)
            foot = QLabel(f"WireGuard · keys never leave their device · v{__version__}")
            foot.setObjectName("foot"); bl.addWidget(foot)

            self.mgr.log = self._log_threadsafe
            self.phase = 0.0
            self.timer = QTimer(self); self.timer.timeout.connect(self._animate); self.timer.start(33)
            self.refresh()

        # ----- small helpers -----
        def _tag(self, text):
            lab = QLabel(text); lab.setObjectName("tag"); return lab

        def _btn(self, text, slot, kind="pick"):
            b = QPushButton(text); b.setObjectName(kind); b.setMinimumHeight(36)
            b.setCursor(Qt.CursorShape.PointingHandCursor); b.clicked.connect(slot); return b

        def _animate(self):
            self.phase += 0.05
            self.header.tick(self.phase)

        def _log_threadsafe(self, message):
            if self.worker is not None and QThread.currentThread() is self.worker:
                self.worker.line.emit(message)
            else:
                self.append_log(message)

        def append_log(self, message):
            self.log.appendPlainText(message)

        def _say(self, message, color=MUTED):
            self.status.setText(message); self.status.setStyleSheet(f"#status{{color:{color};}}")

        def _fail(self, message):
            self._say(message, PINK)

        # Overridable in tests (no modal dialogs there).
        def _confirm(self, title, text):
            return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

        def _ask_save_path(self, suggestion):
            path, _ = QFileDialog.getSaveFileName(self, "Save WireGuard config", suggestion,
                                                  "WireGuard config (*.conf)")
            return path

        def make_qr_dialog(self, name):
            return QrDialog(self, name, self.mgr.config_for(name))

        # ----- state → widgets -----
        def selected(self):
            rows = self.table.selectionModel().selectedRows()
            if not rows:
                return None
            item = self.table.item(rows[0].row(), 0)
            return item.text() if item else None

        def refresh(self):
            state = self.mgr.state
            keep = self.selected()
            self.table.setRowCount(len(state.devices))
            for r, d in enumerate(state.devices):
                st = self.stats.get(d.name)
                values = [d.name, d.address4,
                          human_ago(st["latest_handshake"]) if st else "—",
                          human_bytes(st["rx_bytes"]) if st else "—",
                          human_bytes(st["tx_bytes"]) if st else "—"]
                for c, v in enumerate(values):
                    self.table.setItem(r, c, QTableWidgetItem(v))
                if d.name == keep:
                    self.table.selectRow(r)
            srv = state.server
            if not srv.host:
                text, color = "Enter your server's address and SSH user, then Set up server.", DIM
            elif not srv.public_key:
                text, color = f"{srv.ssh_user}@{srv.host} — not set up yet.", AMBER
            elif state.pending_sync:
                text, color = (f"Ready · server key {fingerprint(srv.public_key)} · "
                               "device changes not on the server yet (Set up server to push them)."), AMBER
            else:
                text, color = (f"Ready · {srv.endpoint} · server key {fingerprint(srv.public_key)} · "
                               f"{len(state.devices)} device(s)"), GREEN
            self.server_state.setText(text); self.server_state.setStyleSheet(f"#hint{{color:{color};}}")
            up = is_connected()
            self.conn.setText("●  This computer is connected through the tunnel" if up
                              else "○  This computer is not connected")
            self.conn.setStyleSheet(f"#conn{{color:{GREEN if up else DIM};}}")

        def save_server(self):
            self.mgr.configure(host=self.host.text().strip(), ssh_user=self.user.text().strip() or "root",
                               ssh_port=self.ssh_port.value(), wg_port=self.wg_port.value(),
                               ssh_key=self.key.text().strip())

        # ----- background work -----
        def _start(self, label, fn, after=None):
            if self.worker:
                return False
            self._set_busy(True)
            self._say(label + "…", CYAN)
            self.worker = Worker(fn)
            self.worker.line.connect(self.append_log)
            self.worker.done.connect(lambda kind, payload: self._finished(kind, payload, after))
            self.worker.start()
            return True

        def _finished(self, kind, payload, after):
            self.worker = None
            self._set_busy(False)
            if kind == "ok":
                if after:
                    after(payload)
            else:
                self._fail(payload)
            self.refresh()

        def _set_busy(self, busy):
            for w in (self.b_setup, self.b_script, self.b_refresh, self.b_add, self.b_qr, self.b_export,
                      self.b_remove, self.b_up, self.b_down, self.host, self.user, self.key,
                      self.ssh_port, self.wg_port, self.new_name):
                w.setEnabled(not busy)

        # ----- actions -----
        def pick_key(self):
            path, _ = QFileDialog.getOpenFileName(self, "Choose an SSH private key")
            if path:
                self.key.setText(path)

        def setup_server(self):
            try:
                self.save_server()
            except TunnelError as exc:
                return self._fail(str(exc))
            self._start("Setting up WireGuard on the server (this can take a minute)", self.mgr.setup_server,
                        lambda key: self._say(f"Server ready. Server key {fingerprint(key)}", GREEN))

        def copy_script(self):
            try:
                self.save_server()
                script = self.mgr.script("setup")
            except TunnelError as exc:
                return self._fail(str(exc))
            QApplication.clipboard().setText(script)
            self._say("Setup script copied. It contains the devices' preshared keys: paste it only into "
                      "your own server's console (as root).", AMBER)

        def refresh_status(self):
            def done(stats):
                self.stats = stats
                self._say("Status updated from the server.", GREEN)
            self._start("Asking the server for handshakes", self.mgr.status, done)

        def add_device(self):
            name = self.new_name.text().strip()
            try:
                device = self.mgr.add_device(name)
            except TunnelError as exc:
                return self._fail(str(exc))
            self.new_name.clear()
            self.refresh()
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).text() == device.name:
                    self.table.selectRow(r)
            if self.mgr.state.server.public_key and self.mgr.state.server.host:
                self._start(f"Adding {device.name} to the server", self.mgr.sync,
                            lambda _r: self._say(f"{device.name} added at {device.address4}. "
                                                 "Use QR code for a phone or Export for a computer.", GREEN))
            else:
                self._say(f"{device.name} created at {device.address4}. Set up the server to activate it.", AMBER)

        def remove_device(self):
            name = self.selected()
            if not name:
                return self._fail("Select a device first.")
            if not self._confirm("Remove device", f"Revoke {name}? Its keys are deleted and it can no "
                                                  "longer connect."):
                return
            try:
                self.mgr.remove_device(name)
            except TunnelError as exc:
                return self._fail(str(exc))
            self.stats.pop(name, None)
            self.refresh()
            if self.mgr.state.server.public_key and self.mgr.state.server.host:
                self._start(f"Revoking {name} on the server", self.mgr.sync,
                            lambda _r: self._say(f"{name} revoked.", GREEN))
            else:
                self._say(f"{name} removed.", GREEN)

        def show_qr(self):
            name = self.selected()
            if not name:
                return self._fail("Select a device first.")
            try:
                dialog = self.make_qr_dialog(name)
            except TunnelError as exc:
                return self._fail(str(exc))
            dialog.exec()

        def export_conf(self):
            name = self.selected()
            if not name:
                return self._fail("Select a device first.")
            path = self._ask_save_path(f"{name}.conf")
            if not path:
                return
            try:
                written = self.mgr.export(name, path)
            except TunnelError as exc:
                return self._fail(str(exc))
            self._say(f"Saved {written}. It contains the private key; import it into WireGuard, "
                      "then delete it.", GREEN)

        def connect_up(self):
            name = self.selected()
            if not name:
                return self._fail("Select which device this computer is.")
            self._start(f"Connecting as {name}", lambda: self.mgr.up(name, gui=True),
                        lambda plan: self._say(f"Connected as {name} via {plan.method}.", GREEN))

        def connect_down(self):
            self._start("Disconnecting", lambda: self.mgr.down(gui=True),
                        lambda _p: self._say("Disconnected.", GREEN))

    return QApplication, TunnelWindow


STYLE = f"""
#body {{ background: {BG}; }}
QWidget {{ color: {INK}; font-family: Helvetica, Arial, sans-serif; font-size: 13px; }}
QDialog {{ background: {PANEL}; }}
#card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 14px; }}
#tag {{ color: {MUTED}; font-weight: bold; font-size: 11px; letter-spacing: 1px; }}
#hint {{ color: {DIM}; font-size: 11px; }}
#status {{ color: {MUTED}; font-size: 12px; }}
#conn {{ color: {DIM}; font-size: 12px; font-weight: bold; }}
#foot {{ color: {DIM}; font-family: "Courier New", monospace; font-size: 10px; }}
#log {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 9px; color: {LAVENDER};
        font-family: "Courier New", monospace; font-size: 11px; }}
QLineEdit, QSpinBox {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 9px;
            padding: 7px 10px; color: {INK}; selection-background-color: {VIOLET}; }}
QLineEdit:focus, QSpinBox:focus {{ border: 1px solid {CYAN}; }}
QTableWidget {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 9px;
                gridline-color: {LINE}; selection-background-color: {VIOLET}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; border: none; padding: 6px;
                        font-weight: bold; font-size: 11px; }}
QPushButton#pick {{ background: {PANEL_HI}; border: 1px solid {LAVENDER}; border-radius: 9px;
                    color: {INK}; font-weight: bold; padding: 0 14px; }}
QPushButton#pick:hover {{ background: #1b2150; }}
QPushButton#go {{ background: {CYAN}; color: {BG}; border: none; border-radius: 9px;
                  font-weight: bold; padding: 0 16px; }}
QPushButton:disabled {{ background: {PANEL_HI}; color: {DIM}; }}
"""


def launch() -> int:
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except Exception:
        print("PyQt6 is required for the ENVY Tunnel window. Run 'envy-tunnel --help' for the "
              "command-line version.")
        return 2
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("No display found. Run 'envy-tunnel --help' for the command-line version.")
        return 2
    try:
        QApplication, TunnelWindow = _build()
        app = QApplication.instance() or QApplication(sys.argv)
        window = TunnelWindow()
        window.show()
        return app.exec()
    except TunnelError as exc:
        print(f"envy-tunnel: {exc}")
        return 1
