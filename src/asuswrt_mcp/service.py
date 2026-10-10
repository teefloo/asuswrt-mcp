"""Business operations exposed by the MCP server."""

from __future__ import annotations

import binascii
from contextlib import contextmanager, suppress
import socket
from threading import RLock
import time
from collections.abc import Callable
from typing import Any, Literal

from asusrouter.modules.parental_control import (
    KEY_PC_BLOCK_ALL,
    KEY_PC_MAC,
    KEY_PC_NAME,
    KEY_PC_STATE,
    KEY_PC_TIMEMAP,
    KEY_PC_TYPE,
    PCRuleType,
    ParentalControlRule,
    add_rule as add_parental_rule,
    read_pc_rules,
    remove_rule as remove_parental_rule,
    write_pc_rules,
)

from .clients.ssh import AsusRouterSshClient
from .config import Settings, get_settings
from .errors import RouterOperationError, UnsupportedOperationError
from .nvram import (
    parse_dhcp_staticlist,
    parse_port_forwarding,
    remove_dhcp_reservation,
    remove_port_forwarding_rule,
    upsert_dhcp_reservation,
    upsert_port_forwarding_rule,
)
from .responses import tool_ok
from .security import require_mutation
from .serialization import safe_data
from .ssh_parsers import (
    parse_cron_jobs,
    parse_df_output,
    parse_lsmod,
    merge_client_sources,
    parse_dnsmasq_leases,
    parse_ip_rules,
    parse_load_average,
    parse_meminfo,
    parse_mount_output,
    parse_netstat_listeners,
    parse_neighbor_table,
    parse_process_table,
    parse_proc_partitions,
    parse_proc_net_dev,
    parse_route_table,
    parse_uptime_seconds,
)
from .validators import normalize_mac, validate_ip, validate_label, validate_port_range

RESTART_SERVICE_MAP = {
    "httpd": "restart_httpd",
    "firewall": "restart_firewall",
    "wireless": "restart_wireless",
    "dnsmasq": "restart_dnsmasq",
    "openvpnd": "restart_openvpnd",
    "vpnc": "restart_vpnc",
    "wireguard": "restart_wgs",
    "samba": "restart_samba",
}

GUEST_BANDS = {"2g": 0, "5g": 1, "5g2": 2, "6g": 3}
PARENTAL_KEYS = [
    KEY_PC_BLOCK_ALL,
    KEY_PC_MAC,
    KEY_PC_NAME,
    KEY_PC_STATE,
    KEY_PC_TIMEMAP,
    KEY_PC_TYPE,
]
SSH_HEALTH_KEYS = [
    "productid",
    "buildno",
    "extendno",
    "http_enable",
    "http_lanport",
    "https_lanport",
    "lan_ipaddr",
    "wan0_ipaddr",
    "wan0_gateway",
    "wl0_radio",
    "wl1_radio",
]
SSH_SNAPSHOT_KEYS = [
    "productid",
    "buildno",
    "extendno",
    "lan_ipaddr",
    "lan_netmask",
    "wan0_ipaddr",
    "wan0_gateway",
    "http_enable",
    "http_lanport",
    "https_lanport",
    "wl0_ssid",
    "wl1_ssid",
    "wl0_radio",
    "wl1_radio",
    "wl0.1_ssid",
    "wl0.1_bss_enabled",
    "wl0.2_ssid",
    "wl0.2_bss_enabled",
    "wl0.3_ssid",
    "wl0.3_bss_enabled",
    "wl1.1_ssid",
    "wl1.1_bss_enabled",
    "wl1.2_ssid",
    "wl1.2_bss_enabled",
    "wl1.3_ssid",
    "wl1.3_bss_enabled",
    "vts_enable_x",
    "vts_rulelist",
    "dhcp_staticlist",
    *PARENTAL_KEYS,
]
GUEST_KEYS = [
    "wl0.1_ssid",
    "wl0.1_bss_enabled",
    "wl0.1_lanaccess",
    "wl0.2_ssid",
    "wl0.2_bss_enabled",
    "wl0.2_lanaccess",
    "wl0.3_ssid",
    "wl0.3_bss_enabled",
    "wl0.3_lanaccess",
    "wl1.1_ssid",
    "wl1.1_bss_enabled",
    "wl1.1_lanaccess",
    "wl1.2_ssid",
    "wl1.2_bss_enabled",
    "wl1.2_lanaccess",
    "wl1.3_ssid",
    "wl1.3_bss_enabled",
    "wl1.3_lanaccess",
]
WIRELESS_KEYS = [
    "productid",
    "wl0_ssid",
    "wl1_ssid",
    "wl0_radio",
    "wl1_radio",
    *GUEST_KEYS,
]
NETWORK_KEYS = [
    "lan_ipaddr",
    "lan_netmask",
    "wan0_ipaddr",
    "wan0_gateway",
]
LAN_KEYS = [
    "lan_ifname",
    "lan_ipaddr",
    "lan_netmask",
    "lan_proto",
    "lan_domain",
    "dhcp_enable_x",
]
WEB_ADMIN_KEYS = ["http_enable", "http_lanport", "https_lanport"]
WAN_KEYS = [
    "wan0_proto",
    "wan0_ifname",
    "wan0_ipaddr",
    "wan0_gateway",
    "wan0_dns",
    "wan0_state_t",
]
DHCP_CONFIG_KEYS = [
    "dhcp_enable_x",
    "dhcp_start",
    "dhcp_end",
    "dhcp_lease",
    "lan_domain",
    "dhcp_staticlist",
]
TIME_SYNC_KEYS = [
    "time_zone",
    "time_zone_x",
    "ntp_server0",
    "ntp_server1",
    "ntp_ready",
]
DNS_KEYS = ["wan0_dns", "dhcp_dns1_x", "dhcp_dns2_x", "dnsfilter_enable_x"]
IPV6_KEYS = [
    "ipv6_service",
    "ipv6_prefix",
    "ipv6_prefix_length",
    "ipv6_rtr_addr",
    "ipv6_dnsenable",
]
ADMIN_ACCESS_KEYS = [
    "sshd_enable",
    "sshd_port",
    "sshd_wan",
    "telnetd_enable",
    *WEB_ADMIN_KEYS,
]
VPN_KEYS = ["vpn_serverx_start_x", "vpnc_clientlist", "wgs_enable"]
UPNP_KEYS = ["upnp_enable", "upnp_proto", "upnp_clean_int"]
DDNS_KEYS = [
    "ddns_enable_x",
    "ddns_hostname_x",
    "ddns_server_x",
    "ddns_updated",
    "ddns_status",
]
SAMBA_KEYS = ["enable_samba", "st_samba_mode"]
SERVICE_STATUS_COMMAND = (
    "ps | grep -E 'httpd|httpds|dnsmasq|openvpn|vpn|wg|dropbear|telnetd|smbd|nmbd' "
    "| grep -v grep || true"
)
DF_COMMAND = "df -k 2>/dev/null || true"
MOUNTS_COMMAND = "mount 2>/dev/null || true"
ROUTES_COMMAND = "ip route show 2>/dev/null || true"
RULES_COMMAND = "ip rule show 2>/dev/null || true"
PARTITIONS_COMMAND = "cat /proc/partitions 2>/dev/null || true"
NET_DEV_COMMAND = "cat /proc/net/dev 2>/dev/null || true"
LSMOD_COMMAND = "lsmod 2>/dev/null || true"
NETSTAT_COMMAND = "netstat -lntup 2>/dev/null || true"
CRON_COMMAND = "cru l 2>/dev/null || true"
CONNTRACK_COUNT_COMMAND = (
    "cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true"
)
CONNTRACK_MAX_COMMAND = (
    "cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true"
)


class RouterService:
    """Coordinates safe router operations through allowlisted SSH only."""

    def __init__(
        self,
        settings_factory: Callable[[], Settings] = get_settings,
        ssh_client_cls: type[AsusRouterSshClient] = AsusRouterSshClient,
    ) -> None:
        self._settings_factory = settings_factory
        self._ssh_client_cls = ssh_client_cls
        self._ssh_lock = RLock()
        self._shared_ssh: AsusRouterSshClient | None = None
        self.last_snapshot: dict[str, Any] = {}

    @property
    def settings(self) -> Settings:
        return self._settings_factory()

    def close(self) -> None:
        with self._ssh_lock:
            if self._shared_ssh is not None:
                self._shared_ssh.close()
                self._shared_ssh = None

    @contextmanager
    def _managed_ssh(self):
        with self._ssh_lock:
            client = self._shared_ssh
            if client is None or not client.is_connected:
                if client is not None:
                    with suppress(Exception):
                        client.close()
                client = self._ssh_client_cls(self.settings)
                client.connect()
                self._shared_ssh = client
            try:
                yield client
            except Exception:
                with suppress(Exception):
                    client.close()
                if self._shared_ssh is client:
                    self._shared_ssh = None
                raise

    def capabilities(self) -> dict[str, Any]:
        settings = self.settings
        return {
            "server": "asuswrt-mcp",
            "transport": "stdio",
            "configured": {
                "http": False,
                "ssh": bool(settings.host and settings.effective_ssh_username),
            },
            "connection_mode": "ssh-only",
            "mutations_enabled": settings.allow_mutations,
            "safety": {
                "requires_confirm": True,
                "supports_dry_run": True,
                "arbitrary_ssh": False,
                "firmware_flash": False,
                "factory_reset": False,
            },
            "tools": [
                "asuswrt_health",
                "asuswrt_ssh_diagnostics",
                "asuswrt_identity",
                "asuswrt_system_stats",
                "asuswrt_network_overview",
                "asuswrt_lan_details",
                "asuswrt_wan_details",
                "asuswrt_dns_config",
                "asuswrt_ipv6_status",
                "asuswrt_dhcp_config",
                "asuswrt_time_sync",
                "asuswrt_web_admin",
                "asuswrt_admin_access",
                "asuswrt_clients",
                "asuswrt_dhcp_leases",
                "asuswrt_arp_neighbors",
                "asuswrt_service_processes",
                "asuswrt_wireless_overview",
                "asuswrt_guest_networks",
                "asuswrt_interface_stats",
                "asuswrt_open_ports",
                "asuswrt_kernel_modules",
                "asuswrt_cron_jobs",
                "asuswrt_conntrack_status",
                "asuswrt_samba_status",
                "asuswrt_usb_overview",
                "asuswrt_storage_usage",
                "asuswrt_mounts",
                "asuswrt_partitions",
                "asuswrt_route_table",
                "asuswrt_policy_routing",
                "asuswrt_vpn_overview",
                "asuswrt_upnp_status",
                "asuswrt_ddns_status",
                "asuswrt_config_snapshot",
                "asuswrt_capabilities",
                "asuswrt_restart_service",
                "asuswrt_dhcp_server",
                "asuswrt_upnp",
                "asuswrt_radio",
                "asuswrt_guest_wifi",
                "asuswrt_guest_lan_access",
                "asuswrt_port_forwarding",
                "asuswrt_vpn_server",
                "asuswrt_parental_access",
                "asuswrt_parental_block_all",
                "asuswrt_dhcp_reservation",
            ],
            "allowlists": {
                "restart_services": sorted(RESTART_SERVICE_MAP),
                "guest_bands": sorted(GUEST_BANDS),
            },
            "settings": settings.safe_dict(),
        }

    def _ssh_health_snapshot(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            nvram = ssh.get_nvram_many(SSH_HEALTH_KEYS)
            uptime = ssh.run_command("cat /proc/uptime").stdout
            loadavg = ssh.run_command("cat /proc/loadavg").stdout
            meminfo = ssh.run_command("cat /proc/meminfo").stdout

        buildno = nvram.get("buildno", "")
        extendno = nvram.get("extendno", "")
        firmware = f"{buildno}_{extendno}".strip("_")
        return {
            "identity": {
                "model": nvram.get("productid", ""),
                "firmware": firmware,
                "buildno": buildno,
                "extendno": extendno,
            },
            "health": {
                "uptime_seconds": parse_uptime_seconds(uptime),
                "load_average": parse_load_average(loadavg),
                "memory_kb": parse_meminfo(meminfo),
                "lan_ip": nvram.get("lan_ipaddr", ""),
                "wan_ip": nvram.get("wan0_ipaddr", ""),
                "wan_gateway": nvram.get("wan0_gateway", ""),
                "wireless_radios": {
                    "2g": nvram.get("wl0_radio", "") == "1",
                    "5g": nvram.get("wl1_radio", "") == "1",
                },
                "web_admin": {
                    "http_enabled": nvram.get("http_enable", "") == "1",
                    "http_port": nvram.get("http_lanport", ""),
                    "https_port": nvram.get("https_lanport", ""),
                },
            },
            "source": "ssh",
        }

    def _ssh_tcp_probe_data(self) -> dict[str, Any]:
        settings = self.settings
        settings.require_ssh()
        started_at = time.perf_counter()
        try:
            with socket.create_connection(
                (settings.host or "", settings.ssh_port),
                timeout=settings.timeout_seconds,
            ) as connection:
                peer_host, peer_port = connection.getpeername()
            return {
                "ok": True,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "peer": f"{peer_host}:{peer_port}",
            }
        except Exception as exc:  # noqa: BLE001 - return probe diagnostics
            return {
                "ok": False,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "error": str(exc),
            }

    def _ssh_banner_probe_data(self) -> dict[str, Any]:
        settings = self.settings
        settings.require_ssh()
        started_at = time.perf_counter()
        try:
            with socket.create_connection(
                (settings.host or "", settings.ssh_port),
                timeout=settings.timeout_seconds,
            ) as connection:
                connection.settimeout(settings.timeout_seconds)
                connection.sendall(b"SSH-2.0-asuswrt-mcp-probe\r\n")
                payload = connection.recv(768)

            banner = ""
            kex_payload = b""
            if b"\n" in payload:
                banner_bytes, remainder = payload.split(b"\n", 1)
                banner = banner_bytes.decode(errors="replace").strip()
                kex_payload = remainder
            else:
                banner = payload.decode(errors="replace").strip()

            return {
                "ok": bool(banner),
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "banner": banner,
                "kex_bytes_received": len(kex_payload),
                "kex_preview_hex": binascii.hexlify(kex_payload[:64]).decode(),
            }
        except Exception as exc:  # noqa: BLE001 - return probe diagnostics
            return {
                "ok": False,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "error": str(exc),
            }

    def _ssh_auth_probe_data(self) -> dict[str, Any]:
        settings = self.settings
        settings.require_ssh()
        started_at = time.perf_counter()
        client = self._ssh_client_cls(settings)
        try:
            client.connect()
            command_result = client.run_command("echo ssh-ok")
            remote_version = ""
            host_key_type = ""
            try:
                transport = client.client.get_transport()
                remote_version = getattr(transport, "remote_version", "") or ""
                server_key = transport.get_remote_server_key() if transport else None
                host_key_type = server_key.get_name() if server_key else ""
            except Exception:
                remote_version = ""
                host_key_type = ""
            return {
                "ok": True,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "command": command_result.command,
                "command_output": command_result.stdout,
                "remote_version": remote_version,
                "server_host_algorithm": host_key_type,
            }
        except Exception as exc:  # noqa: BLE001 - return probe diagnostics
            return {
                "ok": False,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 1),
                "error": str(exc),
            }
        finally:
            with suppress(Exception):
                client.close()

    def _ssh_clients_snapshot(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            leases_raw = ssh.run_command(
                "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"
            ).stdout
            clientlist_raw = ssh.run_command(
                "cat /tmp/clientlist.json 2>/dev/null || true"
            ).stdout
            neighbors_raw = ssh.run_command("ip neigh show 2>/dev/null || true").stdout

        clients = merge_client_sources(
            leases_raw=leases_raw,
            clientlist_raw=clientlist_raw,
            neighbors_raw=neighbors_raw,
        )
        return {
            "clients": clients,
            "lease_count": len(clients),
            "source": "ssh",
        }

    def _guest_entries_from_nvram(self, raw: dict[str, str]) -> list[dict[str, Any]]:
        guest_wifi = []
        for band, index in (("2g", 0), ("5g", 1)):
            for slot in (1, 2, 3):
                ssid = raw.get(f"wl{index}.{slot}_ssid", "")
                enabled = raw.get(f"wl{index}.{slot}_bss_enabled", "") == "1"
                lan_access = raw.get(f"wl{index}.{slot}_lanaccess", "").lower() == "on"
                if ssid or enabled:
                    guest_wifi.append(
                        {
                            "band": band,
                            "slot": slot,
                            "ssid": ssid,
                            "enabled": enabled,
                            "lan_access": lan_access,
                        }
                    )
        return guest_wifi

    def _ssh_parental_snapshot(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(PARENTAL_KEYS)
        return {
            "enabled": raw.get(KEY_PC_STATE, "") == "1",
            "block_all": raw.get(KEY_PC_BLOCK_ALL, "") == "1",
            "rules": list(read_pc_rules(raw).values()),
            "source": "ssh",
        }

    def _ssh_port_forwarding_snapshot_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(["vts_enable_x", "vts_rulelist"])
        return {
            "enabled": raw.get("vts_enable_x") == "1",
            "rules": parse_port_forwarding(raw.get("vts_rulelist", "")),
            "source": "ssh",
        }

    def _ssh_config_snapshot_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(SSH_SNAPSHOT_KEYS)

        buildno = raw.get("buildno", "")
        extendno = raw.get("extendno", "")
        wireless = []
        for band, index in (("2g", 0), ("5g", 1)):
            wireless.append(
                {
                    "band": band,
                    "ssid": raw.get(f"wl{index}_ssid", ""),
                    "enabled": raw.get(f"wl{index}_radio", "") == "1",
                }
            )

        guest_wifi = self._guest_entries_from_nvram(raw)

        return {
            "identity": {
                "model": raw.get("productid", ""),
                "firmware": f"{buildno}_{extendno}".strip("_"),
                "buildno": buildno,
                "extendno": extendno,
            },
            "network": {
                "lan_ip": raw.get("lan_ipaddr", ""),
                "lan_netmask": raw.get("lan_netmask", ""),
                "wan_ip": raw.get("wan0_ipaddr", ""),
                "wan_gateway": raw.get("wan0_gateway", ""),
                "web_admin": {
                    "http_enabled": raw.get("http_enable", "") == "1",
                    "http_port": raw.get("http_lanport", ""),
                    "https_port": raw.get("https_lanport", ""),
                },
            },
            "wireless": wireless,
            "guest_wifi": guest_wifi,
            "dhcp": {
                "reservations": parse_dhcp_staticlist(raw.get("dhcp_staticlist", ""))
            },
            "port_forwarding": {
                "enabled": raw.get("vts_enable_x") == "1",
                "rules": parse_port_forwarding(raw.get("vts_rulelist", "")),
            },
            "parental_control": {
                "enabled": raw.get(KEY_PC_STATE, "") == "1",
                "block_all": raw.get(KEY_PC_BLOCK_ALL, "") == "1",
                "rules": list(read_pc_rules(raw).values()),
            },
            "source": "ssh",
        }

    def _ssh_identity_data(self) -> dict[str, Any]:
        snapshot = self._ssh_health_snapshot()
        return {**snapshot["identity"], "source": "ssh"}

    def _ssh_system_stats_data(self) -> dict[str, Any]:
        snapshot = self._ssh_health_snapshot()
        return {**snapshot["health"], "source": "ssh"}

    def _ssh_network_overview_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many([*NETWORK_KEYS, *WEB_ADMIN_KEYS])
        return {
            "lan_ip": raw.get("lan_ipaddr", ""),
            "lan_netmask": raw.get("lan_netmask", ""),
            "wan_ip": raw.get("wan0_ipaddr", ""),
            "wan_gateway": raw.get("wan0_gateway", ""),
            "web_admin": {
                "http_enabled": raw.get("http_enable", "") == "1",
                "http_port": raw.get("http_lanport", ""),
                "https_port": raw.get("https_lanport", ""),
            },
            "source": "ssh",
        }

    def _ssh_web_admin_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(WEB_ADMIN_KEYS)
            processes = parse_process_table(ssh.run_command(SERVICE_STATUS_COMMAND).stdout)
        web_processes = [
            process
            for process in processes
            if process["name"] in {"httpd", "httpds"}
        ]
        return {
            "http_enabled": raw.get("http_enable", "") == "1",
            "http_port": raw.get("http_lanport", ""),
            "https_port": raw.get("https_lanport", ""),
            "processes": web_processes,
            "source": "ssh",
        }

    def _ssh_dhcp_leases_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            leases_raw = ssh.run_command(
                "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"
            ).stdout
        leases = parse_dnsmasq_leases(leases_raw)
        return {"leases": leases, "lease_count": len(leases), "source": "ssh"}

    def _ssh_neighbors_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            neighbors_raw = ssh.run_command("ip neigh show 2>/dev/null || true").stdout
        neighbors = list(parse_neighbor_table(neighbors_raw).values())
        return {"neighbors": neighbors, "neighbor_count": len(neighbors), "source": "ssh"}

    def _ssh_service_processes_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            processes_raw = ssh.run_command(SERVICE_STATUS_COMMAND).stdout
        processes = parse_process_table(processes_raw)
        return {"processes": processes, "process_count": len(processes), "source": "ssh"}

    def _ssh_wireless_overview_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(WIRELESS_KEYS)
            leases_raw = ssh.run_command(
                "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"
            ).stdout
            clientlist_raw = ssh.run_command(
                "cat /tmp/clientlist.json 2>/dev/null || true"
            ).stdout
            neighbors_raw = ssh.run_command("ip neigh show 2>/dev/null || true").stdout

        clients = merge_client_sources(
            leases_raw=leases_raw,
            clientlist_raw=clientlist_raw,
            neighbors_raw=neighbors_raw,
        )
        band_counts = {"2G": 0, "5G": 0, "wired": 0}
        for client in clients:
            connection = client.get("connection")
            band = str(client.get("band", "")).upper()
            if connection == "wired":
                band_counts["wired"] += 1
            elif band in band_counts:
                band_counts[band] += 1

        return {
            "radios": [
                {
                    "band": "2g",
                    "ssid": raw.get("wl0_ssid", ""),
                    "enabled": raw.get("wl0_radio", "") == "1",
                },
                {
                    "band": "5g",
                    "ssid": raw.get("wl1_ssid", ""),
                    "enabled": raw.get("wl1_radio", "") == "1",
                },
            ],
            "guest_networks": self._guest_entries_from_nvram(raw),
            "connected_counts": band_counts,
            "source": "ssh",
        }

    def _ssh_guest_networks_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(GUEST_KEYS)
        guest_networks = self._guest_entries_from_nvram(raw)
        return {
            "guest_networks": guest_networks,
            "guest_network_count": len(guest_networks),
            "source": "ssh",
        }

    def _ssh_storage_usage_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            df_raw = ssh.run_command(DF_COMMAND).stdout
        filesystems = parse_df_output(df_raw)
        return {
            "filesystems": filesystems,
            "filesystem_count": len(filesystems),
            "source": "ssh",
        }

    def _ssh_mounts_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            mounts_raw = ssh.run_command(MOUNTS_COMMAND).stdout
        mounts = parse_mount_output(mounts_raw)
        return {"mounts": mounts, "mount_count": len(mounts), "source": "ssh"}

    def _ssh_partitions_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            partitions_raw = ssh.run_command(PARTITIONS_COMMAND).stdout
        partitions = parse_proc_partitions(partitions_raw)
        return {
            "partitions": partitions,
            "partition_count": len(partitions),
            "source": "ssh",
        }

    def _ssh_route_table_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            routes_raw = ssh.run_command(ROUTES_COMMAND).stdout
        routes = parse_route_table(routes_raw)
        return {"routes": routes, "route_count": len(routes), "source": "ssh"}

    def _ssh_policy_routing_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            rules_raw = ssh.run_command(RULES_COMMAND).stdout
        rules = parse_ip_rules(rules_raw)
        return {"rules": rules, "rule_count": len(rules), "source": "ssh"}

    def _ssh_wan_details_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(WAN_KEYS)
        dns_servers = [server for server in raw.get("wan0_dns", "").split() if server]
        return {
            "protocol": raw.get("wan0_proto", ""),
            "interface": raw.get("wan0_ifname", ""),
            "ip": raw.get("wan0_ipaddr", ""),
            "gateway": raw.get("wan0_gateway", ""),
            "dns_servers": dns_servers,
            "state": raw.get("wan0_state_t", ""),
            "source": "ssh",
        }

    def _ssh_lan_details_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(LAN_KEYS)
        return {
            "interface": raw.get("lan_ifname", ""),
            "ip": raw.get("lan_ipaddr", ""),
            "netmask": raw.get("lan_netmask", ""),
            "protocol": raw.get("lan_proto", ""),
            "domain": raw.get("lan_domain", ""),
            "dhcp_enabled": raw.get("dhcp_enable_x", "") == "1",
            "source": "ssh",
        }

    def _ssh_dhcp_config_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(DHCP_CONFIG_KEYS)
        reservations = parse_dhcp_staticlist(raw.get("dhcp_staticlist", ""))
        return {
            "enabled": raw.get("dhcp_enable_x", "") == "1",
            "pool_start": raw.get("dhcp_start", ""),
            "pool_end": raw.get("dhcp_end", ""),
            "lease_time": raw.get("dhcp_lease", ""),
            "domain": raw.get("lan_domain", ""),
            "reservations": reservations,
            "reservation_count": len(reservations),
            "source": "ssh",
        }

    def _ssh_dns_config_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(DNS_KEYS)
        lan_dns = [
            server
            for server in (raw.get("dhcp_dns1_x", ""), raw.get("dhcp_dns2_x", ""))
            if server
        ]
        return {
            "wan_dns_servers": [server for server in raw.get("wan0_dns", "").split() if server],
            "lan_dns_servers": lan_dns,
            "dns_filter_enabled": raw.get("dnsfilter_enable_x", "") == "1",
            "source": "ssh",
        }

    def _ssh_ipv6_status_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(IPV6_KEYS)
        return {
            "service": raw.get("ipv6_service", ""),
            "prefix": raw.get("ipv6_prefix", ""),
            "prefix_length": raw.get("ipv6_prefix_length", ""),
            "router_address": raw.get("ipv6_rtr_addr", ""),
            "dns_enabled": raw.get("ipv6_dnsenable", "") == "1",
            "source": "ssh",
        }

    def _ssh_time_sync_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(TIME_SYNC_KEYS)
        ntp_servers = [
            server
            for server in (raw.get("ntp_server0", ""), raw.get("ntp_server1", ""))
            if server
        ]
        return {
            "timezone": raw.get("time_zone_x", "") or raw.get("time_zone", ""),
            "ntp_servers": ntp_servers,
            "synced": raw.get("ntp_ready", "") == "1",
            "source": "ssh",
        }

    def _ssh_admin_access_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(ADMIN_ACCESS_KEYS)
            processes_raw = ssh.run_command(SERVICE_STATUS_COMMAND).stdout
        processes = [
            process
            for process in parse_process_table(processes_raw)
            if process["name"] in {"httpd", "httpds", "dropbear", "telnetd"}
        ]
        return {
            "web_admin": {
                "http_enabled": raw.get("http_enable", "") == "1",
                "http_port": raw.get("http_lanport", ""),
                "https_port": raw.get("https_lanport", ""),
            },
            "ssh_admin": {
                "enabled": raw.get("sshd_enable", "") == "1",
                "port": raw.get("sshd_port", ""),
                "wan_enabled": raw.get("sshd_wan", "") == "1",
            },
            "telnet_admin": {
                "enabled": raw.get("telnetd_enable", "") == "1",
            },
            "processes": processes,
            "source": "ssh",
        }

    def _ssh_vpn_overview_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(VPN_KEYS)
            processes_raw = ssh.run_command(SERVICE_STATUS_COMMAND).stdout
        processes = [
            process
            for process in parse_process_table(processes_raw)
            if any(token in process["command"] for token in ("openvpn", "vpn", "wg"))
        ]
        return {
            "openvpn_server_enabled": raw.get("vpn_serverx_start_x", "") == "1",
            "vpn_client_profiles_configured": bool(raw.get("vpnc_clientlist", "")),
            "wireguard_enabled": raw.get("wgs_enable", "") == "1",
            "processes": processes,
            "process_count": len(processes),
            "source": "ssh",
        }

    def _ssh_upnp_status_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(UPNP_KEYS)
        return {
            "enabled": raw.get("upnp_enable", "") == "1",
            "protocol": raw.get("upnp_proto", ""),
            "clean_interval": raw.get("upnp_clean_int", ""),
            "source": "ssh",
        }

    def _ssh_ddns_status_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(DDNS_KEYS)
        return {
            "enabled": raw.get("ddns_enable_x", "") == "1",
            "hostname": raw.get("ddns_hostname_x", ""),
            "provider": raw.get("ddns_server_x", ""),
            "updated": raw.get("ddns_updated", ""),
            "status": raw.get("ddns_status", ""),
            "source": "ssh",
        }

    def _ssh_interface_stats_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            netdev_raw = ssh.run_command(NET_DEV_COMMAND).stdout
        interfaces = parse_proc_net_dev(netdev_raw)
        return {
            "interfaces": interfaces,
            "interface_count": len(interfaces),
            "source": "ssh",
        }

    def _ssh_open_ports_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            netstat_raw = ssh.run_command(NETSTAT_COMMAND).stdout
        listeners = parse_netstat_listeners(netstat_raw)
        return {
            "listeners": listeners,
            "listener_count": len(listeners),
            "source": "ssh",
        }

    def _ssh_kernel_modules_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            lsmod_raw = ssh.run_command(LSMOD_COMMAND).stdout
        modules = parse_lsmod(lsmod_raw)
        return {
            "modules": modules,
            "module_count": len(modules),
            "source": "ssh",
        }

    def _ssh_cron_jobs_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            cron_raw = ssh.run_command(CRON_COMMAND).stdout
        jobs = parse_cron_jobs(cron_raw)
        return {"jobs": jobs, "job_count": len(jobs), "source": "ssh"}

    def _ssh_conntrack_status_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            count_raw = ssh.run_command(CONNTRACK_COUNT_COMMAND).stdout
            max_raw = ssh.run_command(CONNTRACK_MAX_COMMAND).stdout
        try:
            count = int(count_raw.strip() or 0)
        except ValueError:
            count = 0
        try:
            maximum = int(max_raw.strip() or 0)
        except ValueError:
            maximum = 0
        utilization = round((count / maximum) * 100, 2) if maximum else 0.0
        return {
            "count": count,
            "max": maximum,
            "utilization_percent": utilization,
            "source": "ssh",
        }

    def _ssh_samba_status_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(SAMBA_KEYS)
            processes_raw = ssh.run_command(SERVICE_STATUS_COMMAND).stdout
        processes = [
            process
            for process in parse_process_table(processes_raw)
            if process["name"] in {"smbd", "nmbd"}
        ]
        return {
            "enabled": raw.get("enable_samba", "") == "1",
            "mode": raw.get("st_samba_mode", ""),
            "processes": processes,
            "process_count": len(processes),
            "source": "ssh",
        }

    def _ssh_usb_overview_data(self) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            partitions_raw = ssh.run_command(PARTITIONS_COMMAND).stdout
            mounts_raw = ssh.run_command(MOUNTS_COMMAND).stdout
            df_raw = ssh.run_command(DF_COMMAND).stdout
        partitions = parse_proc_partitions(partitions_raw)
        mounts = parse_mount_output(mounts_raw)
        filesystems = parse_df_output(df_raw)
        usb_partitions = [
            partition
            for partition in partitions
            if partition["name"].startswith(("sd", "hd", "mmc"))
        ]
        usb_mounts = [
            mount
            for mount in mounts
            if mount["source"].startswith(("/dev/sd", "/dev/hd", "/dev/mmc"))
        ]
        usb_filesystems = [
            filesystem
            for filesystem in filesystems
            if filesystem["filesystem"].startswith(("/dev/sd", "/dev/hd", "/dev/mmc"))
        ]
        return {
            "partitions": usb_partitions,
            "mounts": usb_mounts,
            "filesystems": usb_filesystems,
            "usb_present": bool(usb_partitions or usb_mounts or usb_filesystems),
            "source": "ssh",
        }

    async def identity(self) -> dict[str, Any]:
        data = self._ssh_identity_data()
        return tool_ok("asuswrt_identity", data=data)

    async def system_stats(self) -> dict[str, Any]:
        data = self._ssh_system_stats_data()
        return tool_ok("asuswrt_system_stats", data=data)

    async def network_overview(self) -> dict[str, Any]:
        data = self._ssh_network_overview_data()
        return tool_ok("asuswrt_network_overview", data=data)

    async def lan_details(self) -> dict[str, Any]:
        data = self._ssh_lan_details_data()
        return tool_ok("asuswrt_lan_details", data=data)

    async def web_admin(self) -> dict[str, Any]:
        data = self._ssh_web_admin_data()
        return tool_ok("asuswrt_web_admin", data=data)

    async def dhcp_leases(self) -> dict[str, Any]:
        data = self._ssh_dhcp_leases_data()
        return tool_ok("asuswrt_dhcp_leases", data=data)

    async def arp_neighbors(self) -> dict[str, Any]:
        data = self._ssh_neighbors_data()
        return tool_ok("asuswrt_arp_neighbors", data=data)

    async def service_processes(self) -> dict[str, Any]:
        data = self._ssh_service_processes_data()
        return tool_ok("asuswrt_service_processes", data=data)

    async def wireless_overview(self) -> dict[str, Any]:
        data = self._ssh_wireless_overview_data()
        return tool_ok("asuswrt_wireless_overview", data=data)

    async def guest_networks(self) -> dict[str, Any]:
        data = self._ssh_guest_networks_data()
        return tool_ok("asuswrt_guest_networks", data=data)

    async def storage_usage(self) -> dict[str, Any]:
        data = self._ssh_storage_usage_data()
        return tool_ok("asuswrt_storage_usage", data=data)

    async def mounts(self) -> dict[str, Any]:
        data = self._ssh_mounts_data()
        return tool_ok("asuswrt_mounts", data=data)

    async def partitions(self) -> dict[str, Any]:
        data = self._ssh_partitions_data()
        return tool_ok("asuswrt_partitions", data=data)

    async def route_table(self) -> dict[str, Any]:
        data = self._ssh_route_table_data()
        return tool_ok("asuswrt_route_table", data=data)

    async def policy_routing(self) -> dict[str, Any]:
        data = self._ssh_policy_routing_data()
        return tool_ok("asuswrt_policy_routing", data=data)

    async def wan_details(self) -> dict[str, Any]:
        data = self._ssh_wan_details_data()
        return tool_ok("asuswrt_wan_details", data=data)

    async def dns_config(self) -> dict[str, Any]:
        data = self._ssh_dns_config_data()
        return tool_ok("asuswrt_dns_config", data=data)

    async def ipv6_status(self) -> dict[str, Any]:
        data = self._ssh_ipv6_status_data()
        return tool_ok("asuswrt_ipv6_status", data=data)

    async def dhcp_config(self) -> dict[str, Any]:
        data = self._ssh_dhcp_config_data()
        return tool_ok("asuswrt_dhcp_config", data=data)

    async def time_sync(self) -> dict[str, Any]:
        data = self._ssh_time_sync_data()
        return tool_ok("asuswrt_time_sync", data=data)

    async def admin_access(self) -> dict[str, Any]:
        data = self._ssh_admin_access_data()
        return tool_ok("asuswrt_admin_access", data=data)

    async def vpn_overview(self) -> dict[str, Any]:
        data = self._ssh_vpn_overview_data()
        return tool_ok("asuswrt_vpn_overview", data=data)

    async def upnp_status(self) -> dict[str, Any]:
        data = self._ssh_upnp_status_data()
        return tool_ok("asuswrt_upnp_status", data=data)

    async def ddns_status(self) -> dict[str, Any]:
        data = self._ssh_ddns_status_data()
        return tool_ok("asuswrt_ddns_status", data=data)

    async def interface_stats(self) -> dict[str, Any]:
        data = self._ssh_interface_stats_data()
        return tool_ok("asuswrt_interface_stats", data=data)

    async def open_ports(self) -> dict[str, Any]:
        data = self._ssh_open_ports_data()
        return tool_ok("asuswrt_open_ports", data=data)

    async def kernel_modules(self) -> dict[str, Any]:
        data = self._ssh_kernel_modules_data()
        return tool_ok("asuswrt_kernel_modules", data=data)

    async def cron_jobs(self) -> dict[str, Any]:
        data = self._ssh_cron_jobs_data()
        return tool_ok("asuswrt_cron_jobs", data=data)

    async def conntrack_status(self) -> dict[str, Any]:
        data = self._ssh_conntrack_status_data()
        return tool_ok("asuswrt_conntrack_status", data=data)

    async def samba_status(self) -> dict[str, Any]:
        data = self._ssh_samba_status_data()
        return tool_ok("asuswrt_samba_status", data=data)

    async def usb_overview(self) -> dict[str, Any]:
        data = self._ssh_usb_overview_data()
        return tool_ok("asuswrt_usb_overview", data=data)

    async def health(self) -> dict[str, Any]:
        snapshot = self._ssh_health_snapshot()
        self.last_snapshot = safe_data(snapshot)
        return tool_ok("asuswrt_health", data=snapshot)

    async def ssh_diagnostics(self) -> dict[str, Any]:
        settings = self.settings
        data = {
            "host": settings.host or "",
            "port": settings.ssh_port,
            "username": settings.effective_ssh_username or "",
            "tcp_probe": self._ssh_tcp_probe_data(),
            "banner_probe": self._ssh_banner_probe_data(),
            "auth_probe": self._ssh_auth_probe_data(),
            "shared_session_connected": bool(
                self._shared_ssh and self._shared_ssh.is_connected
            ),
            "source": "ssh",
        }
        return tool_ok("asuswrt_ssh_diagnostics", data=data)

    async def clients(self) -> dict[str, Any]:
        snapshot = self._ssh_clients_snapshot()
        self.last_snapshot = safe_data(snapshot)
        return tool_ok("asuswrt_clients", data=snapshot)

    async def config_snapshot(self) -> dict[str, Any]:
        snapshot = {"config": self._ssh_config_snapshot_data()}
        self.last_snapshot = safe_data(snapshot)
        return tool_ok("asuswrt_config_snapshot", data=snapshot)

    async def restart_service(
        self,
        *,
        service: str,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        service_key = service.lower().strip()
        if service_key not in RESTART_SERVICE_MAP:
            raise UnsupportedOperationError(
                code="unsupported_service",
                message="Service is not allowlisted for restart.",
                details={"service": service, "allowed": sorted(RESTART_SERVICE_MAP)},
            )

        router_service = RESTART_SERVICE_MAP[service_key]
        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        data = {"service": service_key, "router_service": router_service}
        if dry_run:
            return tool_ok("asuswrt_restart_service", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.restart_service(router_service)
        return tool_ok(
            "asuswrt_restart_service",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def dhcp_server(
        self,
        *,
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        data = {"enabled": enabled, "nvram_key": "dhcp_enable_x"}
        if dry_run:
            return tool_ok("asuswrt_dhcp_server", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {"dhcp_enable_x": 1 if enabled else 0},
                commit=True,
                service="restart_dnsmasq",
            )
        return tool_ok(
            "asuswrt_dhcp_server",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def upnp(
        self,
        *,
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        data = {"enabled": enabled, "nvram_key": "upnp_enable"}
        if dry_run:
            return tool_ok("asuswrt_upnp", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {"upnp_enable": 1 if enabled else 0},
                commit=True,
                service="restart_firewall",
            )
        return tool_ok(
            "asuswrt_upnp",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def vpn_server(
        self,
        *,
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        data = {"enabled": enabled, "nvram_key": "vpn_serverx_start_x"}
        if dry_run:
            return tool_ok("asuswrt_vpn_server", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {"vpn_serverx_start_x": 1 if enabled else 0},
                commit=True,
                service="restart_openvpnd",
            )
        return tool_ok(
            "asuswrt_vpn_server",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def wireguard_client(
        self,
        *,
        action: Literal["connect", "disconnect", "restart"],
        unit: int,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if action not in {"connect", "disconnect", "restart"}:
            raise UnsupportedOperationError(
                code="unsupported_vpn_client_action",
                message="WireGuard client action is not supported.",
                details={"action": action, "allowed": ["connect", "disconnect", "restart"]},
            )
        if unit not in range(1, 6):
            raise RouterOperationError(
                code="invalid_vpn_client_unit",
                message="WireGuard client unit must be between 1 and 5.",
                details={"unit": unit},
            )

        nvram_key = f"wgc{unit}_enable"
        with self._managed_ssh() as ssh:
            marker = ssh.get_nvram(nvram_key).strip()
        if marker not in {"0", "1"}:
            raise UnsupportedOperationError(
                code="vpn_client_slot_not_configured",
                message="WireGuard client slot is not configured.",
                details={"unit": unit},
            )

        enabled_before = marker == "1"
        if action == "restart" and not enabled_before:
            raise RouterOperationError(
                code="vpn_client_not_enabled",
                message="WireGuard client must be enabled before it can be restarted.",
                details={"unit": unit},
            )

        enabled_after = {
            "connect": True,
            "disconnect": False,
            "restart": enabled_before,
        }[action]
        service_action = {
            "connect": f"start_wgc {unit}",
            "disconnect": f"stop_wgc {unit}",
            "restart": f"restart_wgc {unit}",
        }[action]
        would_change = action == "restart" or enabled_after != enabled_before
        data = {
            "action": action,
            "unit": unit,
            "configured": True,
            "enabled_before": enabled_before,
            "enabled_after": enabled_after,
            "service_action": service_action,
            "would_change": would_change,
        }

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        if dry_run:
            return tool_ok("asuswrt_wireguard_client", dry_run=True, data=data)
        if not would_change:
            return tool_ok(
                "asuswrt_wireguard_client",
                data={**data, "result": True, "source": "ssh"},
            )

        with self._managed_ssh() as ssh:
            if action == "connect":
                ssh.set_nvram({nvram_key: 1}, commit=True, service=service_action)
            elif action == "disconnect":
                ssh.set_nvram({nvram_key: 0}, commit=True, service=service_action)
            else:
                ssh.restart_service(service_action)
        return tool_ok(
            "asuswrt_wireguard_client",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def guest_wifi(
        self,
        *,
        band: Literal["2g", "5g", "5g2", "6g"],
        slot: int,
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if band not in GUEST_BANDS:
            raise UnsupportedOperationError(
                code="unsupported_guest_band",
                message="Guest Wi-Fi band is not supported.",
                details={"band": band, "allowed": sorted(GUEST_BANDS)},
            )
        if slot not in (1, 2, 3):
            raise RouterOperationError(
                code="invalid_guest_slot",
                message="Guest Wi-Fi slot must be 1, 2, or 3.",
                details={"slot": slot},
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        band_index = GUEST_BANDS[band]
        nvram_key = f"wl{band_index}.{slot}_bss_enabled"
        desired_value = 1 if enabled else 0
        data = {
            "band": band,
            "slot": slot,
            "enabled": enabled,
            "nvram_key": nvram_key,
        }
        if dry_run:
            return tool_ok("asuswrt_guest_wifi", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {nvram_key: desired_value},
                commit=True,
                service="restart_wireless",
            )
        return tool_ok(
            "asuswrt_guest_wifi",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def radio(
        self,
        *,
        band: Literal["2g", "5g", "5g2", "6g"],
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if band not in GUEST_BANDS:
            raise UnsupportedOperationError(
                code="unsupported_radio_band",
                message="Radio band is not supported.",
                details={"band": band, "allowed": sorted(GUEST_BANDS)},
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        band_index = GUEST_BANDS[band]
        nvram_key = f"wl{band_index}_radio"
        data = {
            "band": band,
            "enabled": enabled,
            "nvram_key": nvram_key,
        }
        if dry_run:
            return tool_ok("asuswrt_radio", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {nvram_key: 1 if enabled else 0},
                commit=True,
                service="restart_wireless",
            )
        return tool_ok(
            "asuswrt_radio",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def guest_lan_access(
        self,
        *,
        band: Literal["2g", "5g", "5g2", "6g"],
        slot: int,
        allow_lan: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if band not in GUEST_BANDS:
            raise UnsupportedOperationError(
                code="unsupported_guest_band",
                message="Guest Wi-Fi band is not supported.",
                details={"band": band, "allowed": sorted(GUEST_BANDS)},
            )
        if slot not in (1, 2, 3):
            raise RouterOperationError(
                code="invalid_guest_slot",
                message="Guest Wi-Fi slot must be 1, 2, or 3.",
                details={"slot": slot},
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        band_index = GUEST_BANDS[band]
        nvram_key = f"wl{band_index}.{slot}_lanaccess"
        data = {
            "band": band,
            "slot": slot,
            "allow_lan": allow_lan,
            "nvram_key": nvram_key,
        }
        if dry_run:
            return tool_ok("asuswrt_guest_lan_access", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {nvram_key: "on" if allow_lan else "off"},
                commit=True,
                service="restart_firewall",
            )
        return tool_ok(
            "asuswrt_guest_lan_access",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def port_forwarding(
        self,
        *,
        action: Literal["list", "enable", "disable", "add", "remove"],
        name: str = "",
        ip: str = "",
        port: str = "",
        protocol: Literal["TCP", "UDP", "BOTH"] = "TCP",
        port_external: str = "",
        ip_external: str = "",
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        action = action.lower()  # type: ignore[assignment]
        if action == "list":
            return tool_ok(
                "asuswrt_port_forwarding",
                data=self._ssh_port_forwarding_snapshot_data(),
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        if action in ("enable", "disable"):
            enabled = action == "enable"
            data = {"enabled": enabled}
            if dry_run:
                return tool_ok("asuswrt_port_forwarding", dry_run=True, data=data)
            with self._managed_ssh() as ssh:
                ssh.set_nvram(
                    {"vts_enable_x": 1 if enabled else 0},
                    commit=True,
                    service="restart_firewall",
                )
            return tool_ok(
                "asuswrt_port_forwarding",
                changed=True,
                data={**data, "result": True, "source": "ssh"},
            )

        safe_ip = validate_ip(ip)
        safe_protocol = protocol.upper()
        safe_port_external = validate_port_range(
            port_external or port, "port_external"
        )
        safe_port = validate_port_range(port or port_external, "port")
        safe_name = validate_label(name, "name")
        safe_ip_external = validate_ip(ip_external) if ip_external else ""
        data = {
            "action": action,
            "name": safe_name,
            "ip": safe_ip,
            "port": safe_port,
            "protocol": safe_protocol,
            "port_external": safe_port_external,
            "ip_external": safe_ip_external,
        }
        if dry_run:
            return tool_ok("asuswrt_port_forwarding", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            current = ssh.get_nvram("vts_rulelist")
            if action == "add":
                new_value, changed, rules = upsert_port_forwarding_rule(
                    current,
                    name=safe_name,
                    ip=safe_ip,
                    port=safe_port,
                    protocol=safe_protocol,
                    port_external=safe_port_external,
                    ip_external=safe_ip_external,
                )
            elif action == "remove":
                new_value, changed, rules = remove_port_forwarding_rule(
                    current,
                    ip=safe_ip,
                    port_external=safe_port_external,
                    protocol=safe_protocol,
                    port=safe_port,
                    ip_external=safe_ip_external,
                )
            else:
                raise UnsupportedOperationError(
                    code="unsupported_port_forwarding_action",
                    message="Unsupported port forwarding action.",
                    details={"action": action},
                )
            if changed:
                ssh.set_nvram(
                    {"vts_rulelist": new_value},
                    commit=True,
                    service="restart_firewall",
                )

        return tool_ok(
            "asuswrt_port_forwarding",
            changed=changed,
            data={"rules": rules, "source": "ssh", **data},
        )

    async def parental_access(
        self,
        *,
        action: Literal["list", "enable", "disable", "block", "unblock", "remove"],
        mac: str = "",
        name: str = "",
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        action = action.lower()  # type: ignore[assignment]
        if action == "list":
            return tool_ok(
                "asuswrt_parental_access",
                data={"parental_control": self._ssh_parental_snapshot()},
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        if action in ("enable", "disable"):
            enabled = action == "enable"
            data = {"enabled": enabled}
            if dry_run:
                return tool_ok("asuswrt_parental_access", dry_run=True, data=data)
            with self._managed_ssh() as ssh:
                ssh.set_nvram(
                    {KEY_PC_STATE: 1 if enabled else 0},
                    commit=True,
                    service="restart_firewall",
                )
            return tool_ok(
                "asuswrt_parental_access",
                changed=True,
                data={**data, "result": True, "source": "ssh"},
            )

        safe_mac = normalize_mac(mac)
        safe_name = validate_label(name or safe_mac, "name")
        data = {"action": action, "mac": safe_mac, "name": safe_name}
        if dry_run:
            return tool_ok("asuswrt_parental_access", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            raw = ssh.get_nvram_many(PARENTAL_KEYS)
            current_rules = read_pc_rules(raw)
            if action in ("block", "unblock"):
                rule = ParentalControlRule(
                    mac=safe_mac,
                    name=safe_name,
                    type=PCRuleType.BLOCK
                    if action == "block"
                    else PCRuleType.DISABLE,
                )
                new_rules = add_parental_rule(current_rules, rule)
            elif action == "remove":
                new_rules = remove_parental_rule(current_rules, safe_mac)
            else:
                raise UnsupportedOperationError(
                    code="unsupported_parental_action",
                    message="Unsupported parental access action.",
                    details={"action": action},
                )
            arguments = write_pc_rules(new_rules)
            changed = any(
                raw.get(key, "") != str(value) for key, value in arguments.items()
            )
            if changed:
                ssh.set_nvram(
                    arguments,
                    commit=True,
                    service="restart_firewall",
                )

        return tool_ok(
            "asuswrt_parental_access",
            changed=changed,
            data={
                **data,
                "enabled": raw.get(KEY_PC_STATE, "") == "1",
                "rules": list(new_rules.values()),
                "source": "ssh",
            },
        )

    async def parental_block_all(
        self,
        *,
        enabled: bool,
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        data = {"enabled": enabled}
        if dry_run:
            return tool_ok("asuswrt_parental_block_all", dry_run=True, data=data)

        with self._managed_ssh() as ssh:
            ssh.set_nvram(
                {KEY_PC_BLOCK_ALL: 1 if enabled else 0},
                commit=True,
                service="restart_firewall",
            )
        return tool_ok(
            "asuswrt_parental_block_all",
            changed=True,
            data={**data, "result": True, "source": "ssh"},
        )

    async def dhcp_reservation(
        self,
        *,
        action: Literal["list", "add", "remove"],
        mac: str = "",
        ip: str = "",
        name: str = "",
        confirm: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        with self._managed_ssh() as ssh:
            current = ssh.get_nvram("dhcp_staticlist")

        if action == "list":
            reservations = parse_dhcp_staticlist(current)
            return tool_ok(
                "asuswrt_dhcp_reservation",
                data={"reservations": reservations},
            )

        require_mutation(self.settings.allow_mutations, confirm, dry_run)
        if action == "add":
            new_value, changed, records = upsert_dhcp_reservation(
                current,
                mac=mac,
                ip=ip,
                name=name,
            )
        elif action == "remove":
            new_value, changed, records = remove_dhcp_reservation(current, mac=mac)
        else:
            raise UnsupportedOperationError(
                code="unsupported_dhcp_action",
                message="Unsupported DHCP reservation action.",
                details={"action": action},
            )

        data = {
            "action": action,
            "changed": changed,
            "reservations": records,
        }
        if dry_run:
            return tool_ok(
                "asuswrt_dhcp_reservation",
                changed=False,
                dry_run=True,
                data=data,
            )
        if changed:
            with self._managed_ssh() as ssh:
                ssh.set_nvram(
                    {"dhcp_staticlist": new_value},
                    commit=True,
                    service="restart_dnsmasq",
                )
        return tool_ok(
            "asuswrt_dhcp_reservation",
            changed=changed,
            data=data,
        )

    async def ssh_port_forwarding_snapshot(self) -> dict[str, Any]:
        return tool_ok(
            "asuswrt_port_forwarding",
            data=self._ssh_port_forwarding_snapshot_data(),
        )
