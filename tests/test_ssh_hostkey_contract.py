from __future__ import annotations

import paramiko

from asuswrt_mcp.clients.ssh import AsusRouterSshClient
from asuswrt_mcp.config import Settings


def test_new_ssh_session_never_auto_accepts_unknown_router_host(monkeypatch) -> None:
    observed: dict[str, object] = {}

    class FakeSshClient:
        def load_system_host_keys(self) -> None:
            observed["known_hosts_loaded"] = True

        def set_missing_host_key_policy(self, policy: object) -> None:
            observed["missing_key_policy"] = policy

        def connect(self, **kwargs: object) -> None:
            observed["connection_options"] = kwargs

    monkeypatch.setattr(paramiko, "SSHClient", FakeSshClient)
    AsusRouterSshClient(Settings(host="router.invalid", ssh_username="admin")).connect()

    assert observed.get("known_hosts_loaded") is True
    assert isinstance(observed.get("missing_key_policy"), paramiko.RejectPolicy)
    options = observed.get("connection_options")
    assert isinstance(options, dict)
    assert options["look_for_keys"] is False
    assert options["allow_agent"] is False
