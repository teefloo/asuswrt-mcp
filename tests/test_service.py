from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from asusrouter.modules.parental_control import (
    KEY_PC_BLOCK_ALL,
    KEY_PC_MAC,
    KEY_PC_NAME,
    KEY_PC_STATE,
    KEY_PC_TIMEMAP,
    KEY_PC_TYPE,
)

from asuswrt_mcp.clients.ssh import CommandResult
from asuswrt_mcp.config import Settings
from asuswrt_mcp.service import RouterService


@dataclass
class DummyIdentity:
    model: str = "RT-AX88U"
    firmware: str = "3.0.0.4.388"


class MockHttpClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def __aenter__(self) -> "MockHttpClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def get_identity(self) -> DummyIdentity:
        return DummyIdentity()

    async def get_many(self, data_types: list[str]) -> dict[str, Any]:
        return {item: {"ok": True} for item in data_types}

    async def get_data(self, data_type: str) -> Any:
        if data_type == "clients":
            return [{"mac": "AA:BB:CC:DD:EE:FF"}]
        if data_type == "port_forwarding":
            return {"rules": []}
        if data_type == "parental_control":
            return {"rules": {}}
        return {}

    async def restart_service(self, service: str) -> bool:
        return service == "wireless"

    async def set_guest_wifi(self, *, band: str, slot: int, enabled: bool) -> bool:
        return band == "2g" and slot == 1 and enabled is True

    async def set_port_forwarding_enabled(self, enabled: bool) -> bool:
        return enabled

    async def add_port_forwarding_rule(
        self,
        *,
        name: str,
        ip: str,
        port: str,
        protocol: str,
        port_external: str,
        ip_external: str = "",
    ) -> bool:
        return bool(name and ip and port and protocol and port_external)

    async def remove_port_forwarding_rule(self, **_kwargs: Any) -> list[Any]:
        return []

    async def set_parental_enabled(self, enabled: bool) -> bool:
        return enabled

    async def set_parental_rule(self, **_kwargs: Any) -> bool:
        return True

    async def remove_parental_rule(self, **_kwargs: Any) -> bool:
        return True


class MockSshClient:
    values: dict[str, str] = {
        "dhcp_staticlist": "<AA:BB:CC:DD:EE:FF>192.168.1.20>printer",
        "productid": "RT-AC68U",
        "buildno": "386",
        "extendno": "52062-g06fe188",
        "http_enable": "1",
        "http_lanport": "80",
        "https_lanport": "8443",
        "sshd_enable": "1",
        "sshd_port": "22",
        "sshd_wan": "0",
        "telnetd_enable": "0",
        "lan_ifname": "br0",
        "lan_ipaddr": "192.168.2.1",
        "lan_netmask": "255.255.255.0",
        "lan_proto": "static",
        "dhcp_dns1_x": "192.168.2.1",
        "dhcp_dns2_x": "9.9.9.9",
        "dnsfilter_enable_x": "0",
        "wan0_proto": "dhcp",
        "wan0_ifname": "vlan2",
        "wan0_ipaddr": "192.168.1.10",
        "wan0_gateway": "192.168.1.1",
        "wan0_dns": "1.1.1.1 8.8.8.8",
        "wan0_state_t": "2",
        "ipv6_service": "native",
        "ipv6_prefix": "2a01:cb1a:1234:5600::",
        "ipv6_prefix_length": "64",
        "ipv6_rtr_addr": "2a01:cb1a:1234:5600::1",
        "ipv6_dnsenable": "1",
        "dhcp_enable_x": "1",
        "dhcp_start": "192.168.2.100",
        "dhcp_end": "192.168.2.199",
        "dhcp_lease": "86400",
        "lan_domain": "lan",
        "time_zone": "CET-1CEST,M3.5.0/2,M10.5.0/3",
        "time_zone_x": "Europe/Paris",
        "ntp_server0": "pool.ntp.org",
        "ntp_server1": "time.google.com",
        "ntp_ready": "1",
        "wl0_radio": "1",
        "wl1_radio": "1",
        "wl0_ssid": "Wifi.GENS",
        "wl1_ssid": "Wifi.GENS_5G",
        "wl0.1_ssid": "Guest2G",
        "wl0.1_bss_enabled": "0",
        "wl0.1_lanaccess": "off",
        "wl1.1_ssid": "Guest5G",
        "wl1.1_bss_enabled": "1",
        "wl1.1_lanaccess": "on",
        "vts_enable_x": "1",
        "vts_rulelist": "<Web>8443>192.168.1.10>443>TCP>>",
        "vpn_serverx_start_x": "1",
        "vpnc_clientlist": "<work-vpn>openvpn>",
        "wgs_enable": "0",
        "upnp_enable": "1",
        "upnp_proto": "1",
        "upnp_clean_int": "600",
        "enable_samba": "1",
        "st_samba_mode": "2",
        "ddns_enable_x": "1",
        "ddns_hostname_x": "example.asuscomm.com",
        "ddns_server_x": "WWW.ASUS.COM",
        "ddns_updated": "1",
        "ddns_status": "updated",
        KEY_PC_STATE: "1",
        KEY_PC_BLOCK_ALL: "0",
        KEY_PC_TYPE: "2",
        KEY_PC_MAC: "AA:BB:CC:DD:EE:FF",
        KEY_PC_NAME: "Kid-iPad",
        KEY_PC_TIMEMAP: "W03E21000700<W04122000800",
    }
    writes: list[dict[str, str | int]] = []
    service_calls: list[str] = []
    commands: dict[str, str] = {
        "ps w | grep -E 'syslogd|klogd' | grep -v grep || true": "PID USER VSZ STAT COMMAND\n1 root 100 S syslogd\n2 root 100 S klogd\n",

        "cat /proc/uptime": "48409.39 82525.31",
        "cat /proc/loadavg": "19.32 18.83 16.90 1/160 30524",
        "cat /proc/meminfo": "MemTotal: 255708 kB\nMemFree: 103480 kB\nCached: 17752 kB",
        "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true": (
            "83384 aa:bb:cc:dd:ee:ff 192.168.1.20 printer 01:aa:bb:cc:dd:ee:ff"
        ),
        "cat /tmp/clientlist.json 2>/dev/null || true": (
            '{"AP":{"2G":{"AA:BB:CC:DD:EE:FF":{"ip":"192.168.1.20","rssi":"-43"}}}}'
        ),
        "ip neigh show 2>/dev/null || true": (
            "192.168.1.20 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        ),
        "ps | grep -E 'httpd|httpds|dnsmasq|openvpn|vpn|wg|dropbear|telnetd|smbd|nmbd' | grep -v grep || true": (
            "232 nobody    1264 S    dnsmasq --log-async\n"
            "241 admin    12412 D    httpds -s -i br0 -p 8443\n"
            "242 admin     6536 S    httpd -i br0\n"
            "250 admin     3120 S    dropbear -p 22\n"
            "300 admin     8120 S    openvpn --config server1.conf\n"
            "301 nobody     4096 S    smbd -D\n"
            "302 nobody     2048 S    nmbd -D"
        ),
        "df -k 2>/dev/null || true": (
            "Filesystem           1K-blocks      Used Available Use% Mounted on\n"
            "/dev/root                28672     28672         0 100% /\n"
            "tmpfs                   127852      1248    126604   1% /tmp\n"
            "/dev/sda1             15633408   1048576  14584832   7% /tmp/mnt/USB"
        ),
        "mount 2>/dev/null || true": (
            "/dev/root on / type squashfs (ro,relatime)\n"
            "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,relatime)\n"
            "/dev/sda1 on /tmp/mnt/USB type ext4 (rw,relatime)"
        ),
        "cat /proc/partitions 2>/dev/null || true": (
            "major minor  #blocks  name\n\n"
            "  31        0      28672 mtdblock0\n"
            "   8        1   15633408 sda1"
        ),
        "ip route show 2>/dev/null || true": (
            "default via 192.168.1.1 dev vlan2\n"
            "192.168.2.0/24 dev br0 proto kernel scope link src 192.168.2.1"
        ),
        "ip rule show 2>/dev/null || true": (
            "0: from all lookup local\n"
            "32766: from all lookup main\n"
            "32767: from all lookup default"
        ),
        "cat /proc/net/dev 2>/dev/null || true": (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "  br0: 1234567 1000 0 0 0 0 0 0 7654321 900 0 0 0 0 0 0\n"
            "vlan2: 2345678 1100 0 0 0 0 0 0 6543210 850 0 0 0 0 0 0"
        ),
        "lsmod 2>/dev/null || true": (
            "Module                  Size  Used by\n"
            "nf_conntrack           16384  2\n"
            "iptable_filter          2048  1"
        ),
        "netstat -lntup 2>/dev/null || true": (
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      250/dropbear\n"
            "tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN      241/httpds\n"
            "udp        0      0 0.0.0.0:53              0.0.0.0:*                           232/dnsmasq"
        ),
        "cru l 2>/dev/null || true": (
            "*/5 * * * * service restart_dnsmasq\n"
            "0 3 * * * echo rotate-logs"
        ),
        "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true": "120",
        "cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true": "16384",
    }
    connect_count: int = 0
    close_count: int = 0
    default_values: dict[str, str] = dict(values)
    default_commands: dict[str, str] = dict(commands)

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._connected = False

    def __enter__(self) -> "MockSshClient":
        return self.connect()

    def __exit__(self, *_exc: object) -> None:
        self.close()
        return None

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self) -> "MockSshClient":
        type(self).connect_count += 1
        self._connected = True
        return self

    def close(self) -> None:
        if self._connected:
            type(self).close_count += 1
        self._connected = False

    def get_nvram(self, key: str) -> str:
        return self.values.get(key, "")

    def get_nvram_many(self, keys: list[str]) -> dict[str, str]:
        return {key: self.values.get(key, "") for key in keys}

    def set_nvram(self, values: dict[str, str | int], **_kwargs: Any) -> object:
        self.writes.append(values)
        self.values.update({key: str(value) for key, value in values.items()})
        return object()

    def restart_service(self, service: str) -> object:
        self.service_calls.append(service)
        if service == "restart_logger":
            from asuswrt_mcp.service import LOGGING_PROCESS_COMMAND
            destination = self.values.get("log_ipaddr", "")
            port = self.values.get("log_port", "514")
            forwarding = f" -R {destination}:{port}" if destination else ""
            self.commands[LOGGING_PROCESS_COMMAND] = (
                f"PID USER VSZ STAT COMMAND\n1 root 100 S syslogd{forwarding}\n"
                "2 root 100 S klogd\n"
            )
        return object()

    def run_command(self, command: str) -> CommandResult:
        return CommandResult(
            command=command,
            stdout=self.commands.get(command, ""),
            stderr="",
            exit_status=0,
        )


def make_service(
    *,
    allow_mutations: bool = True,
    prefer_ssh: bool = False,
) -> RouterService:
    MockSshClient.values = dict(MockSshClient.default_values)
    MockSshClient.commands = dict(MockSshClient.default_commands)
    MockSshClient.writes = []
    MockSshClient.service_calls = []
    MockSshClient.connect_count = 0
    MockSshClient.close_count = 0
    settings = Settings(
        host="192.168.1.1",
        username="admin",
        password="password",
        allow_mutations=allow_mutations,
        prefer_ssh=prefer_ssh,
    )
    return RouterService(
        settings_factory=lambda: settings,
        ssh_client_cls=MockSshClient,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_health_updates_last_snapshot() -> None:
    service = make_service()

    response = await service.health()

    assert response["ok"] is True
    assert response["data"]["identity"]["model"] == "RT-AC68U"
    assert response["data"]["source"] == "ssh"
    assert service.last_snapshot["identity"]["model"] == "RT-AC68U"


@pytest.mark.asyncio
async def test_ssh_diagnostics_aggregates_probe_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = make_service()

    monkeypatch.setattr(
        service,
        "_ssh_tcp_probe_data",
        lambda: {"ok": True, "latency_ms": 10.5, "peer": "192.168.1.1:22"},
    )
    monkeypatch.setattr(
        service,
        "_ssh_banner_probe_data",
        lambda: {
            "ok": True,
            "latency_ms": 11.0,
            "banner": "SSH-2.0-dropbear",
            "kex_bytes_received": 32,
            "kex_preview_hex": "00112233",
        },
    )
    monkeypatch.setattr(
        service,
        "_ssh_auth_probe_data",
        lambda: {
            "ok": True,
            "latency_ms": 150.0,
            "command": "echo ssh-ok",
            "command_output": "ssh-ok",
            "remote_version": "SSH-2.0-dropbear",
            "server_host_algorithm": "ssh-ed25519",
        },
    )

    response = await service.ssh_diagnostics()

    assert response["ok"] is True
    assert response["data"]["host"] == "192.168.1.1"
    assert response["data"]["tcp_probe"]["ok"] is True
    assert response["data"]["banner_probe"]["banner"] == "SSH-2.0-dropbear"
    assert response["data"]["auth_probe"]["command_output"] == "ssh-ok"


@pytest.mark.asyncio
async def test_restart_service_requires_mutation_enabled() -> None:
    service = make_service(allow_mutations=False)

    with pytest.raises(Exception) as exc:
        await service.restart_service(service="wireless", confirm=True)

    assert getattr(exc.value, "code") == "mutation_disabled"


@pytest.mark.asyncio
async def test_restart_service_dry_run_without_mutations_enabled() -> None:
    service = make_service(allow_mutations=False)

    response = await service.restart_service(
        service="wireless",
        confirm=False,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True
    assert response["changed"] is False


@pytest.mark.asyncio
async def test_guest_wifi_mutation() -> None:
    service = make_service()

    response = await service.guest_wifi(
        band="2g",
        slot=1,
        enabled=True,
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True


@pytest.mark.asyncio
async def test_dhcp_add_writes_nvram() -> None:
    service = make_service()
    MockSshClient.writes = []

    response = await service.dhcp_reservation(
        action="add",
        mac="11:22:33:44:55:66",
        ip="192.168.1.50",
        name="camera",
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True
    assert MockSshClient.writes
    assert "dhcp_staticlist" in MockSshClient.writes[-1]


@pytest.mark.asyncio
async def test_port_forwarding_add_uses_strict_client_signature() -> None:
    service = make_service()

    response = await service.port_forwarding(
        action="add",
        name="HTTPS",
        ip="192.168.1.20",
        port="8443",
        protocol="TCP",
        port_external="9443",
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True


@pytest.mark.asyncio
async def test_health_uses_ssh_when_preferred() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.health()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["identity"]["model"] == "RT-AC68U"


@pytest.mark.asyncio
async def test_identity_tool_uses_ssh_when_preferred() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.identity()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["firmware"] == "386_52062-g06fe188"


@pytest.mark.asyncio
async def test_system_stats_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.system_stats()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["load_average"]["1m"] == 19.32


@pytest.mark.asyncio
async def test_network_overview_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.network_overview()

    assert response["ok"] is True
    assert response["data"]["lan_ip"] == "192.168.2.1"
    assert response["data"]["web_admin"]["https_port"] == "8443"


@pytest.mark.asyncio
async def test_lan_details_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.lan_details()

    assert response["ok"] is True
    assert response["data"]["interface"] == "br0"
    assert response["data"]["dhcp_enabled"] is True


@pytest.mark.asyncio
async def test_web_admin_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.web_admin()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert len(response["data"]["processes"]) == 2


@pytest.mark.asyncio
async def test_clients_uses_ssh_when_preferred() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.clients()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["clients"][0]["hostname"] == "printer"


@pytest.mark.asyncio
async def test_dhcp_leases_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dhcp_leases()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["lease_count"] == 1


@pytest.mark.asyncio
async def test_arp_neighbors_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.arp_neighbors()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["neighbor_count"] == 1


@pytest.mark.asyncio
async def test_service_processes_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.service_processes()

    assert response["ok"] is True
    assert response["data"]["process_count"] == 7


@pytest.mark.asyncio
async def test_wireless_overview_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wireless_overview()

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["connected_counts"]["2G"] == 1


@pytest.mark.asyncio
async def test_guest_networks_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.guest_networks()

    assert response["ok"] is True
    assert response["data"]["guest_network_count"] == 2


@pytest.mark.asyncio
async def test_storage_usage_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.storage_usage()

    assert response["ok"] is True
    assert response["data"]["filesystem_count"] == 3
    assert response["data"]["filesystems"][1]["mount_point"] == "/tmp"


@pytest.mark.asyncio
async def test_mounts_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.mounts()

    assert response["ok"] is True
    assert response["data"]["mount_count"] == 3
    assert response["data"]["mounts"][0]["filesystem_type"] == "squashfs"


@pytest.mark.asyncio
async def test_partitions_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.partitions()

    assert response["ok"] is True
    assert response["data"]["partition_count"] == 2
    assert response["data"]["partitions"][1]["name"] == "sda1"


@pytest.mark.asyncio
async def test_route_table_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.route_table()

    assert response["ok"] is True
    assert response["data"]["route_count"] == 2
    assert response["data"]["routes"][0]["gateway"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_policy_routing_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.policy_routing()

    assert response["ok"] is True
    assert response["data"]["rule_count"] == 3
    assert response["data"]["rules"][1]["priority"] == 32766


@pytest.mark.asyncio
async def test_wan_details_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wan_details()

    assert response["ok"] is True
    assert response["data"]["protocol"] == "dhcp"
    assert response["data"]["dns_servers"] == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.asyncio
async def test_dns_config_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dns_config()

    assert response["ok"] is True
    assert response["data"]["wan_dns_servers"] == ["1.1.1.1", "8.8.8.8"]
    assert response["data"]["lan_dns_servers"] == ["192.168.2.1", "9.9.9.9"]


@pytest.mark.asyncio
async def test_ipv6_status_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.ipv6_status()

    assert response["ok"] is True
    assert response["data"]["service"] == "native"
    assert response["data"]["dns_enabled"] is True


@pytest.mark.asyncio
async def test_dhcp_config_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dhcp_config()

    assert response["ok"] is True
    assert response["data"]["enabled"] is True
    assert response["data"]["reservation_count"] == 1


@pytest.mark.asyncio
async def test_time_sync_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.time_sync()

    assert response["ok"] is True
    assert response["data"]["timezone"] == "Europe/Paris"
    assert response["data"]["synced"] is True


@pytest.mark.asyncio
async def test_admin_access_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.admin_access()

    assert response["ok"] is True
    assert response["data"]["ssh_admin"]["enabled"] is True
    assert len(response["data"]["processes"]) == 3


@pytest.mark.asyncio
async def test_vpn_overview_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.vpn_overview()

    assert response["ok"] is True
    assert response["data"]["openvpn_server_enabled"] is True
    assert response["data"]["process_count"] == 1


@pytest.mark.asyncio
async def test_upnp_status_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.upnp_status()

    assert response["ok"] is True
    assert response["data"]["enabled"] is True
    assert response["data"]["clean_interval"] == "600"


@pytest.mark.asyncio
async def test_ddns_status_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.ddns_status()

    assert response["ok"] is True
    assert response["data"]["enabled"] is True
    assert response["data"]["hostname"] == "example.asuscomm.com"


@pytest.mark.asyncio
async def test_interface_stats_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.interface_stats()

    assert response["ok"] is True
    assert response["data"]["interface_count"] == 2
    assert response["data"]["interfaces"][0]["interface"] == "br0"


@pytest.mark.asyncio
async def test_open_ports_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.open_ports()

    assert response["ok"] is True
    assert response["data"]["listener_count"] == 3
    assert response["data"]["listeners"][0]["protocol"] == "tcp"


@pytest.mark.asyncio
async def test_kernel_modules_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.kernel_modules()

    assert response["ok"] is True
    assert response["data"]["module_count"] == 2
    assert response["data"]["modules"][0]["name"] == "nf_conntrack"


@pytest.mark.asyncio
async def test_cron_jobs_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.cron_jobs()

    assert response["ok"] is True
    assert response["data"]["job_count"] == 2
    assert response["data"]["jobs"][0]["command"] == "service restart_dnsmasq"


@pytest.mark.asyncio
async def test_conntrack_status_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.conntrack_status()

    assert response["ok"] is True
    assert response["data"]["count"] == 120
    assert response["data"]["max"] == 16384


@pytest.mark.asyncio
async def test_samba_status_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.samba_status()

    assert response["ok"] is True
    assert response["data"]["enabled"] is True
    assert response["data"]["process_count"] == 2


@pytest.mark.asyncio
async def test_usb_overview_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.usb_overview()

    assert response["ok"] is True
    assert response["data"]["usb_present"] is True
    assert response["data"]["partitions"][0]["name"] == "sda1"


@pytest.mark.asyncio
async def test_shared_ssh_session_is_reused_between_tool_calls() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.connect_count = 0
    MockSshClient.close_count = 0

    await service.identity()
    await service.system_stats()
    service.close()

    assert MockSshClient.connect_count == 1
    assert MockSshClient.close_count == 1


@pytest.mark.asyncio
async def test_port_forwarding_list_uses_ssh_when_preferred() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.port_forwarding(action="list")

    assert response["ok"] is True
    assert response["data"]["source"] == "ssh"
    assert response["data"]["enabled"] is True


@pytest.mark.asyncio
async def test_radio_dry_run_uses_mutation_policy() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.radio(
        band="2g",
        enabled=False,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_dhcp_server_dry_run() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.dhcp_server(
        enabled=False,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_upnp_dry_run() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.upnp(
        enabled=False,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_vpn_server_dry_run() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.vpn_server(
        enabled=False,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_guest_lan_access_dry_run() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.guest_lan_access(
        band="2g",
        slot=1,
        allow_lan=True,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_parental_access_list_uses_ssh_when_preferred() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.parental_access(action="list")

    assert response["ok"] is True
    assert response["data"]["parental_control"]["source"] == "ssh"
    assert response["data"]["parental_control"]["enabled"] is True
    assert len(response["data"]["parental_control"]["rules"]) == 1


@pytest.mark.asyncio
async def test_parental_block_all_dry_run() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)

    response = await service.parental_block_all(
        enabled=True,
        dry_run=True,
    )

    assert response["ok"] is True
    assert response["dry_run"] is True


@pytest.mark.asyncio
async def test_port_forwarding_add_writes_nvram_when_preferred() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.writes = []

    response = await service.port_forwarding(
        action="add",
        name="SSH",
        ip="192.168.1.30",
        port="22",
        protocol="TCP",
        port_external="2222",
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True
    assert any("vts_rulelist" in write for write in MockSshClient.writes)


@pytest.mark.asyncio
async def test_dhcp_server_writes_nvram() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.writes = []

    response = await service.dhcp_server(
        enabled=False,
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True
    assert any(write.get("dhcp_enable_x") == 0 for write in MockSshClient.writes)


@pytest.mark.asyncio
async def test_upnp_writes_nvram() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.writes = []

    response = await service.upnp(
        enabled=False,
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True
    assert any(write.get("upnp_enable") == 0 for write in MockSshClient.writes)


@pytest.mark.asyncio
async def test_vpn_server_writes_nvram() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.writes = []

    response = await service.vpn_server(
        enabled=False,
        confirm=True,
    )

    assert response["ok"] is True
    assert response["changed"] is True
    assert any(
        write.get("vpn_serverx_start_x") == 0 for write in MockSshClient.writes
    )

@pytest.mark.asyncio
@pytest.mark.parametrize("destination", ["8.8.8.8", "127.0.0.1", "169.254.1.2", "224.0.0.1", "::1", "192.168.1.2;reboot"])
async def test_remote_syslog_rejects_non_private_ipv4(destination: str) -> None:
    service = make_service(prefer_ssh=True)
    with pytest.raises(Exception) as exc:
        await service.remote_syslog(enabled=True, destination=destination, confirm=True)
    assert getattr(exc.value, "code") == "invalid_syslog_destination"
    assert MockSshClient.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("port", [0, 65536])
async def test_remote_syslog_rejects_invalid_port(port: int) -> None:
    service = make_service(prefer_ssh=True)
    with pytest.raises(Exception) as exc:
        await service.remote_syslog(enabled=True, destination="192.168.2.10", port=port, confirm=True)
    assert getattr(exc.value, "code") == "invalid_syslog_port"
    assert MockSshClient.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed,confirm,code", [(False, True, "mutation_disabled"), (True, False, "confirmation_required")])
async def test_remote_syslog_keeps_mutation_guards(allowed: bool, confirm: bool, code: str) -> None:
    service = make_service(prefer_ssh=True, allow_mutations=allowed)
    with pytest.raises(Exception) as exc:
        await service.remote_syslog(enabled=True, destination="192.168.2.10", confirm=confirm)
    assert getattr(exc.value, "code") == code
    assert MockSshClient.writes == []


@pytest.mark.asyncio
async def test_remote_syslog_dry_run_never_writes_or_exposes_destination() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=False)
    result = await service.remote_syslog(enabled=True, destination="192.168.2.10", dry_run=True)
    assert result["dry_run"] is True
    assert "192.168.2.10" not in str(result)
    assert MockSshClient.writes == []
    assert MockSshClient.service_calls == []


@pytest.mark.asyncio
async def test_remote_syslog_changes_only_destination_port_and_verifies() -> None:
    service = make_service(prefer_ssh=True)
    before = dict(MockSshClient.values)
    result = await service.remote_syslog(enabled=True, destination="192.168.2.10", port=1514, confirm=True)
    assert result["changed"] is True
    assert result["data"]["verified"] is True
    assert MockSshClient.writes == [{"log_ipaddr": "192.168.2.10", "log_port": "1514"}]
    assert MockSshClient.service_calls == ["restart_logger"]
    assert all(MockSshClient.values[k] == v for k, v in before.items() if k not in {"log_ipaddr", "log_port"})
    again = await service.remote_syslog(enabled=True, destination="192.168.2.10", port=1514, confirm=True)
    assert again["changed"] is False
    assert len(MockSshClient.writes) == 1


@pytest.mark.asyncio
async def test_remote_syslog_disable_preserves_port_and_local_logging() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.values.update({"log_ipaddr": "192.168.2.10", "log_port": "1514"})
    result = await service.remote_syslog(enabled=False, confirm=True)
    assert result["data"]["verified"] is True
    assert MockSshClient.writes == [{"log_ipaddr": ""}]
    assert MockSshClient.values["log_port"] == "1514"


@pytest.mark.asyncio
async def test_remote_syslog_failed_readback_is_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    service = make_service(prefer_ssh=True)
    monkeypatch.setattr(MockSshClient, "set_nvram", lambda self, values, **kwargs: None)
    with pytest.raises(Exception) as exc:
        await service.remote_syslog(enabled=True, destination="192.168.2.10", confirm=True)
    assert getattr(exc.value, "code") == "syslog_readback_mismatch"


@pytest.mark.asyncio
async def test_remote_syslog_repairs_runtime_only_without_nvram_write() -> None:
    from asuswrt_mcp.service import LOGGING_PROCESS_COMMAND
    service = make_service(prefer_ssh=True)
    MockSshClient.values.update({"log_ipaddr": "192.168.2.10", "log_port": "514"})
    MockSshClient.commands[LOGGING_PROCESS_COMMAND] = "PID USER VSZ STAT COMMAND\n1 root 100 S syslogd\n"
    preview = await service.remote_syslog(enabled=True, destination="192.168.2.10", dry_run=True)
    assert preview["data"]["configuration_change_required"] is False
    assert preview["data"]["runtime_restart_required"] is True
    result = await service.remote_syslog(enabled=True, destination="192.168.2.10", confirm=True)
    assert result["changed"] is True and result["data"]["verified"] is True
    assert MockSshClient.writes == []
    assert MockSshClient.service_calls == ["restart_logger"]


@pytest.mark.asyncio
async def test_remote_syslog_does_not_accept_stored_state_with_inactive_forwarder(monkeypatch) -> None:
    service = make_service(prefer_ssh=True)
    monkeypatch.setattr(MockSshClient, "restart_service", lambda self, service: None)
    with pytest.raises(Exception) as exc:
        await service.remote_syslog(enabled=True, destination="192.168.2.10", confirm=True)
    assert getattr(exc.value, "code") == "syslog_runtime_mismatch"
