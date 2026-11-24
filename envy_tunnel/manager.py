"""One place that does the work, shared by the command line and the app window."""

from __future__ import annotations

from pathlib import Path

from . import connect, keys, server
from .model import Device, State, TunnelError, client_config, parse_wg_dump
from .store import Store, write_private


class Manager:
    def __init__(self, store: Store | None = None, runner=server.default_runner, log=print,
                 interactive: bool = False):
        self.store = store or Store()
        self.runner = runner
        self.log = log
        self.interactive = interactive
        self.state = self.store.load()

    # ----- local state -------------------------------------------------
    def save(self) -> None:
        self.store.save(self.state)

    def configure(self, **fields) -> None:
        srv = self.state.server
        moved = any(k in fields and fields[k] != getattr(srv, k)
                    for k in ("host", "wg_port", "interface", "subnet4", "subnet6"))
        for name, value in fields.items():
            if value is None or not hasattr(srv, name):
                continue
            setattr(srv, name, value)
        srv.validate()
        if moved and srv.public_key:
            # A different server or interface: the old key no longer applies.
            srv.public_key = ""
            self.state.pending_sync = True
        self.save()

    def _psks(self) -> dict:
        secrets = self.store.load_secrets()
        return {name: entry.get("preshared_key", "") for name, entry in secrets.items()}

    def add_device(self, name: str) -> Device:
        private = keys.generate_private_key()
        device = self.state.add_device(name, keys.public_key(private))
        secrets = self.store.load_secrets()
        secrets[device.name] = {"private_key": private, "preshared_key": keys.generate_preshared_key()}
        self.store.save_secrets(secrets)
        self.save()
        return device

    def remove_device(self, name: str) -> Device:
        device = self.state.remove_device(name)
        secrets = self.store.load_secrets()
        secrets.pop(device.name, None)
        self.store.save_secrets(secrets)
        self.save()
        return device

    def config_for(self, name: str, full_tunnel: bool = True) -> str:
        device = self.state.device(name)
        entry = self.store.load_secrets().get(device.name)
        if not entry:
            raise TunnelError(f"The keys for {name!r} aren't on this computer (it was added elsewhere).")
        return client_config(self.state, device, entry["private_key"], entry["preshared_key"], full_tunnel)

    def export(self, name: str, path, full_tunnel: bool = True) -> Path:
        path = Path(path)
        if path.exists():
            raise TunnelError(f"{path} already exists; ENVY never overwrites files.")
        return write_private(path, self.config_for(name, full_tunnel))

    # ----- server ------------------------------------------------------
    def script(self, kind: str) -> str:
        if kind == "setup":
            return server.setup_script(self.state, self._psks())
        if kind == "sync":
            return server.sync_script(self.state, self._psks())
        if kind == "status":
            return server.status_script(self.state)
        if kind == "uninstall":
            return server.uninstall_script(self.state)
        raise TunnelError(f"Unknown script {kind!r}.")

    def _run(self, kind: str, timeout: int = 600) -> server.Result:
        argv = server.ssh_argv(self.state.server, interactive=self.interactive)
        self.log(f"↳ {' '.join(argv)}   (sending the {kind} script on stdin)")
        code, out, err = self.runner(argv, self.script(kind), timeout)
        result = server.parse_output(code, out, err)
        for step in result.steps:
            self.log("  · " + step)
        return result

    def _learn_key(self, key: str) -> None:
        if not key:
            return
        if not keys.is_key(key):
            raise TunnelError("The server returned an invalid public key.")
        self.state.server.public_key = key

    def setup_server(self) -> str:
        result = self._run("setup", timeout=900)
        self._learn_key(result.server_key)
        self.state.pending_sync = False
        self.save()
        return self.state.server.public_key

    def sync(self) -> None:
        result = self._run("sync")
        self._learn_key(result.server_key)
        self.state.pending_sync = False
        self.save()

    def status(self) -> dict:
        result = self._run("status", timeout=60)
        self._learn_key(result.server_key)
        self.save()
        peers = parse_wg_dump(server.dump_section(result.stdout))
        out = {}
        for d in self.state.devices:
            out[d.name] = peers.get(d.public_key, {"endpoint": "", "latest_handshake": 0,
                                                   "rx_bytes": 0, "tx_bytes": 0})
        return out

    def uninstall_server(self) -> None:
        self._run("uninstall", timeout=120)
        self.state.server.public_key = ""
        self.state.pending_sync = True
        self.save()

    def set_server_key(self, key: str) -> None:
        if not keys.is_key(key):
            raise TunnelError("Not a valid WireGuard public key.")
        self.state.server.public_key = key.strip()
        self.save()

    # ----- this computer -----------------------------------------------
    def up(self, name: str, gui: bool = False, run=None, tools=None, platform=None) -> connect.Plan:
        conf = write_private(self.store.connect_path(), self.config_for(name))
        plan = connect.plan_up(conf, platform=platform, tools=tools)
        kwargs = {"run": run} if run else {}
        connect.execute(plan, gui=gui, log=self.log, platform=platform, **kwargs)
        return plan

    def down(self, gui: bool = False, run=None, tools=None, platform=None) -> connect.Plan:
        plan = connect.plan_down(self.store.connect_path(), platform=platform, tools=tools)
        kwargs = {"run": run} if run else {}
        connect.execute(plan, gui=gui, log=self.log, platform=platform, **kwargs)
        conf = self.store.connect_path()
        if conf.exists():
            conf.unlink()
        return plan
