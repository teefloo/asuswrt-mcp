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
        "webs_update_enable": "1",
        "webs_update_beta": "0",
        "webs_state_update": "1",
        "webs_state_flag": "1",
        "webs_state_error": "0",
        "webs_state_info": "3004_388_99999-gabcdef0",
        "webs_state_level": "2",
        "webs_state_url": "https://private-download.example.invalid/firmware.trx?token=secret",
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
        "dnsfilter_mode": "0",
        "dnsfilter_custom1": "1.1.1.1",
        "dnsfilter_custom2": "9.9.9.9",
        "dnsfilter_custom3": "8.8.8.8",
        "dnsfilter_rulelist": "<AA:BB:CC:DD:EE:FF>8",
        "dnspriv_enable": "1",
        "dnspriv_profile": "2",
        "dnspriv_rulelist": "<private-dot.example.invalid>853>private-spki-marker",
        "dnssec_enable": "1",
        "dnssec_check_unsigned_x": "0",
        "fw_enable_x": "1",
        "fw_dos_x": "0",
        "fw_log_x": "none",
        "misc_ping_x": "1",
        "ipv6_fw_enable": "1",
        "autofw_enable_x": "1",
        "autofw_rulelist": "<private-trigger>192.168.2.55>1234>tcp<private-trigger-2>192.168.2.56>4321>udp",
        "dmz_ip": "192.168.2.123",
        "ipv6_fw_rulelist": "<private-ipv6-rule>2001:db8::1",
        "url_rulelist": "<blocked.example.invalid>",
        "keyword_rulelist": "<private-keyword>",
        "fw_pt_h323": "1",
        "fw_pt_ipsec": "1",
        "fw_pt_l2tp": "0",
        "fw_pt_pppoerelay": "0",
        "fw_pt_pptp": "1",
        "fw_pt_rtsp": "0",
        "fw_pt_sip": "1",
        "qos_enable": "1",
        "qos_type": "1",
        "qos_method": "0",
        "qos_ibw": "102400",
        "qos_obw": "10240",
        "qos_rulelist": "<Web>>80>tcp>0~512>0<HTTPS>>443>tcp>0~512>0",
        "qos_bw_rulelist": "<AA:BB:CC:DD:EE:FF>192.168.2.50>5120>1024>1",
        "wrs_protect_enable": "1",
        "wrs_mals_enable": "1",
        "wrs_vp_enable": "1",
        "wrs_cc_enable": "1",
        "bwdpi_dpi_ver": "2.0.5",
        "bwdpi_sig_ver": "2.516",
        "bwdpi_db_enable": "1",
        "bwdpi_wh_enable": "1",
        "apps_analysis": "1",
        "rstats_enable": "1",
        "cstats_enable": "0",
        "rstats_path": "/jffs/private-rstats-path-must-never-be-returned",
        "enable_ftp": "1",
        "st_ftp_mode": "2",
        "ftp_wanac": "0",
        "ftp_tls": "1",
        "dms_enable": "1",
        "dms_dir": "/tmp/mnt/private-media-dir-must-never-be-returned",
        "enable_webdav": "0",
        "webdav_aidisk": "0",
        "webdav_proxy": "0",
        "webdav_last_login_info": "private-webdav-login-must-never-be-returned",
        "enable_cloudsync": "0",
        "modem_enable": "1",
        "modem_running": "0",
        "wan0_is_usb_modem_ready": "0",
        "wan1_is_usb_modem_ready": "0",
        "modem_user": "private-modem-user-must-never-be-returned",
        "modem_pass": "private-modem-pass-must-never-be-returned",
        "usb_printer": "0",
        "printer_status_t": "0",
        "pptpd_enable": "0",
        "pptpd_clients": "private-pptp-client-must-never-be-returned",
        "ipsec_server_enable": "1",
        "ipsec_client_enable": "0",
        "ipsec_profile_1": "private-ipsec-profile-must-never-be-returned",
        "cfg_recount": "2",
        "cfg_re_maxnum": "9",
        "cfg_relist": "<AA:BB:CC:DD:EE:01>AA:BB:CC:DD:EE:02>AA:BB:CC:DD:EE:03>1735815219<AA:BB:CC:DD:EE:11>AA:BB:CC:DD:EE:12>AA:BB:CC:DD:EE:13>1735815220",
        "cfg_wifi_quality": "-65",
        "amas_lanctrl_service_ready": "1",
        "vlan_enable": "1",
        "vlan_rulelist": "<profile-a>10>tagged>private-segment<profile-b>20>untagged>iot-segment",
        "vlan_pvid_list": "<lan1>10",
        "wgn_vlan_flag": "1",
        "wgn_brif_rulelist": "<br1>10>guest-a<br2>20>guest-b",
        "gvlan_rulelist": "<guest-profile>30>isolated",
        "switch_wantag": "manual",
        "switch_wan0tagid": "300",
        "wans_dualwan": "wan usb",
        "wans_mode": "fo",
        "wans_lb_ratio": "3:1",
        "wans_routing_enable": "1",
        "wans_routing_rulelist": "<192.168.2.50>wan<192.168.2.60>usb",
        "wans_cap": "wan usb lan",
        "wan_unit": "0",
        "wan0_enable": "1",
        "wan1_enable": "1",
        "wan1_proto": "dhcp",
        "wan1_state_t": "0",
        "wan0_auxstate_t": "0",
        "wan1_auxstate_t": "0",
        "wan0_sbstate_t": "0",
        "wan1_sbstate_t": "0",
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
        "wl2_radio": "1",
        "wl0_ifname": "eth4",
        "wl1_ifname": "eth5",
        "wl2_ifname": "eth6",
        "wl0_nband": "2",
        "wl1_nband": "1",
        "wl2_nband": "1",
        "wl0_timesched": "1",
        "wl1_timesched": "0",
        "wl2_timesched": "1",
        "wl0_radio_date_x": "1111100",
        "wl1_radio_date_x": "1111111",
        "wl2_radio_date_x": "1010101",
        "wl0_radio_time_x": "07002300",
        "wl1_radio_time_x": "00002359",
        "wl2_radio_time_x": "06002230",
        "wl0_radio_time2_x": "09002200",
        "wl1_radio_time2_x": "00002359",
        "wl2_radio_time2_x": "08002300",
        "wl0_sched_v2": "",
        "wl1_sched_v2": "",
        "wl2_sched_v2": "opaque-v2-schedule-must-never-be-returned",
        "wl0_channel": "",
        "wl1_channel": "0",
        "wl2_channel": "",
        "wl0_bw": "0",
        "wl1_bw": "0",
        "wl2_bw": "0",
        "wl0_auth_mode_x": "psk2",
        "wl1_auth_mode_x": "psk2",
        "wl2_auth_mode_x": "psk2",
        "wl0_crypto": "aes",
        "wl1_crypto": "aes",
        "wl2_crypto": "aes",
        "wl0_closed": "0",
        "wl1_closed": "0",
        "wl2_closed": "1",
        "wps_enable": "1",
        "wps_enable_x": "1",
        "wps_band_x": "1",
        "wps_proc_status": "0",
        "wps_sta_pin": "12345670-must-never-be-returned",
        "smart_connect_x": "1",
        "scb_smart_connect_x": "1",
        "rast_weak_rssi_diff": "10",
        "wl0_user_rssi": "-70",
        "wl1_user_rssi": "-72",
        "wl2_user_rssi": "-68",
        "wl0_wps_mode": "enabled",
        "wl1_wps_mode": "disabled",
        "wl2_wps_mode": "disabled",
        "wl0_wps_config_state": "1",
        "wl1_wps_config_state": "0",
        "wl2_wps_config_state": "0",
        "wl0_wps_reg": "enabled",
        "wl1_wps_reg": "enabled",
        "wl2_wps_reg": "enabled",
        "wl0_nmode_x": "1",
        "wl1_nmode_x": "8",
        "wl2_nmode_x": "0",
        "wl0_txbf": "1",
        "wl1_txbf": "1",
        "wl2_txbf": "1",
        "wl0_mumimo": "1",
        "wl1_mumimo": "1",
        "wl2_mumimo": "1",
        "wl0_atf": "0",
        "wl1_atf": "0",
        "wl2_atf": "1",
        "wl0_11ax": "0",
        "wl1_11ax": "1",
        "wl2_11ax": "1",
        "wl0_ofdma": "0",
        "wl1_ofdma": "3",
        "wl2_ofdma": "3",
        "wl0_twt": "0",
        "wl1_twt": "0",
        "wl2_twt": "0",
        "wl0_acs_dfs": "0",
        "wl1_acs_dfs": "1",
        "wl2_acs_dfs": "1",
        "wl0_dfs_bw_fallback": "0",
        "wl1_dfs_bw_fallback": "0",
        "wl2_dfs_bw_fallback": "1",
        "wl0_txpower": "100",
        "wl1_txpower": "80",
        "wl2_txpower": "90",
        "wl0_bsd_steering_policy": "AA:BB:CC:DD:EE:99-must-never-be-returned",
        "wl0_wpa_psk": "must-never-be-returned",
        "wl0_ssid": "Wifi.GENS",
        "wl1_ssid": "Wifi.GENS_5G",
        "wl2_ssid": "Wifi.GENS_5G_2",
        "wl0.1_ssid": "Guest2G",
        "wl0.1_bss_enabled": "0",
        "wl0.1_lanaccess": "off",
        "wl1.1_ssid": "Guest5G",
        "wl1.1_bss_enabled": "1",
        "wl1.1_lanaccess": "on",
        "vts_enable_x": "1",
        "vts_rulelist": "<Web>8443>192.168.1.10>443>TCP>>",
        "vpn_serverx_start_x": "1",
        "VPNClient_enable": "1",
        "vpnc_clientlist": "<legacy-private-endpoint>legacy-private-user>secret-profile",
        "vpnc_dev_policy_list": "<AA:BB:CC:DD:EE:FF>1>private-device-policy",
        "vpnc_policy_unit": "1",
        "wgs_enable": "0",
        "wgc1_enable": "1",
        "wgc2_enable": "0",
        "wgc3_enable": "",
        "wgc4_enable": "",
        "wgc5_enable": "",
        "vpnc_clientlist": "<work-vpn>openvpn>",
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
        "log_ipaddr": "192.168.2.200",
        "log_port": "514",
        "log_level": "6",
        "log_size": "256",
        "log_path": "/jffs/private-syslog-must-never-be-returned",
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
        "cat /proc/uptime": "48409.39 82525.31",
        "ps | grep -E 'syslogd|klogd' | grep -v grep || true": (
            "1779 admin 3100 S /sbin/syslogd -m 0 -S -R 192.168.2.200:514 -O /jffs/private-syslog-must-never-be-returned -s 256 -l\n"
            "1781 admin 3100 S /sbin/klogd -c 5"
        ),
        "ps | grep -E 'rstats|cstats' | grep -v grep || true": (
            "400 admin 1200 S rstats"
        ),
        "ps | grep -E 'vsftpd|ftpd|minidlna|u2ec|lpd|p910|pptpd|charon|pluto|ipsec' | grep -v grep || true": (
            "501 admin 1400 S vsftpd\n"
            "502 admin 1500 S minidlna\n"
            "503 admin 1600 S charon"
        ),
        "ps | grep -E 'roamast|bsd|wps_monitor' | grep -v grep || true": (
            "111 admin 1234 S roamast\n"
            "222 admin 1234 S bsd"
        ),
        "wl -i eth4 chanspec 2>/dev/null || true": "10 (0x100a)",
        "wl -i eth5 chanspec 2>/dev/null || true": "52/160 (0xec32)",
        "wl -i eth6 chanspec 2>/dev/null || true": "100/160 (0xe872)",
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

    def set_nvram(self, values: dict[str, str | int], **kwargs: Any) -> object:
        self.writes.append(values)
        service = kwargs.get("service")
        if service:
            self.service_calls.append(str(service))
        self.values.update({key: str(value) for key, value in values.items()})
        return object()

    def restart_service(self, service: str) -> object:
        self.service_calls.append(service)
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
async def test_firewall_status_tool_reports_safe_summary() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.firewall_status()

    assert response["ok"] is True
    assert response["data"] == {
        "enabled": True,
        "dos_protection_enabled": False,
        "logging": "none",
        "wan_ping_response_enabled": True,
        "ipv6_firewall_enabled": True,
        "port_triggering_enabled": True,
        "port_trigger_rule_count": 2,
        "dmz_configured": True,
        "ipv6_rule_count": 1,
        "url_filter_rule_count": 1,
        "content_filter_rule_count": 1,
        "nat_passthrough": {
            "h323": True,
            "ipsec": True,
            "l2tp": False,
            "pppoe_relay": False,
            "pptp": True,
            "rtsp": False,
            "sip": True,
        },
        "source": "ssh",
    }
    serialized = str(response)
    for sensitive in (
        "192.168.2.123",
        "private-trigger",
        "private-ipv6-rule",
        "blocked.example.invalid",
        "private-keyword",
    ):
        assert sensitive not in serialized


@pytest.mark.asyncio
async def test_wireless_config_reports_all_radios_without_psk_material() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wireless_config()

    assert response["ok"] is True
    radios = response["data"]["radios"]
    assert response["data"]["radio_count"] == 3
    assert [radio["band_label"] for radio in radios] == [
        "2.4ghz", "5ghz-1", "5ghz-2"
    ]
    assert [radio["configured_channel"] for radio in radios] == [
        "auto", "auto", "auto"
    ]
    assert [radio["current_channel"] for radio in radios] == [10, 52, 100]
    assert [radio["current_bandwidth_mhz"] for radio in radios] == [
        None, 160, 160
    ]
    assert radios[2]["hidden"] is True
    serialized = str(response).lower()
    assert "must-never-be-returned" not in serialized
    assert "wpa_psk" not in serialized
    assert "psk_material" not in serialized


@pytest.mark.asyncio
async def test_dns_filter_status_redacts_resolvers_and_rules_to_counts() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dns_filter_status()

    assert response["ok"] is True
    assert response["data"] == {
        "enabled": False,
        "global_mode": "0",
        "custom_resolver_count": 3,
        "client_rule_count": 1,
        "source": "ssh",
    }
    serialized = str(response)
    assert "1.1.1.1" not in serialized
    assert "9.9.9.9" not in serialized
    assert "8.8.8.8" not in serialized
    assert "AA:BB:CC:DD:EE:FF" not in serialized


@pytest.mark.asyncio
async def test_dns_privacy_status_redacts_resolver_rules() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dns_privacy_status()

    assert response["ok"] is True
    assert response["data"] == {
        "dns_over_tls_enabled": True,
        "dns_over_tls_profile_code": 2,
        "dns_over_tls_rule_count": 1,
        "dnssec_enabled": True,
        "dnssec_check_unsigned_enabled": False,
        "source": "ssh",
    }
    serialized = str(response)
    assert "private-dot.example.invalid" not in serialized
    assert "private-spki-marker" not in serialized


@pytest.mark.asyncio
async def test_qos_status_redacts_rule_payloads_and_decodes_type() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.qos_status()

    assert response["ok"] is True
    assert response["data"] == {
        "enabled": True,
        "configured_type_code": 1,
        "configured_type": "adaptive",
        "method_code": 0,
        "inbound_bandwidth_kbit": 102400,
        "outbound_bandwidth_kbit": 10240,
        "rule_count": 2,
        "bandwidth_rule_count": 1,
        "source": "ssh",
    }
    serialized = str(response)
    assert "AA:BB:CC:DD:EE:FF" not in serialized
    assert "192.168.2.50" not in serialized
    assert "HTTPS" not in serialized


@pytest.mark.asyncio
async def test_aiprotection_status_reports_features_without_event_payloads() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.aiprotection_status()

    assert response["ok"] is True
    assert response["data"] == {
        "enabled": True,
        "malicious_sites_blocking_enabled": True,
        "two_way_ips_enabled": True,
        "infected_device_prevention_enabled": True,
        "dpi_version": "2.0.5",
        "signature_version": "2.516",
        "source": "ssh",
    }
    serialized = str(response).lower()
    assert "threat_event" not in serialized
    assert "event_log" not in serialized
    assert "history" not in serialized
    assert "client" not in serialized


@pytest.mark.asyncio
async def test_aimesh_status_reports_counts_without_node_identifiers() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.aimesh_status()

    assert response["ok"] is True
    assert response["data"] == {
        "configured_node_count": 2,
        "max_node_count": 9,
        "topology_record_count": 2,
        "topology_count_consistent": True,
        "controller_ready": True,
        "wifi_quality_threshold_dbm": -65,
        "source": "ssh",
    }
    serialized = str(response)
    assert "AA:BB:CC:DD:EE:01" not in serialized
    assert "AA:BB:CC:DD:EE:11" not in serialized
    assert "cfg_relist" not in serialized


@pytest.mark.asyncio
async def test_wps_status_excludes_pin_material() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wps_status()

    assert response["ok"] is True
    assert response["data"]["enabled"] is True
    assert response["data"]["selected_band_code"] == 1
    assert response["data"]["process_status_code"] == 0
    assert response["data"]["radio_count"] == 3
    assert response["data"]["radios"][0]["mode"] == "enabled"
    assert response["data"]["radios"][0]["config_state_code"] == 1
    serialized = str(response).lower()
    assert "12345670" not in serialized
    assert "sta_pin" not in serialized
    assert "wps_pin" not in serialized


@pytest.mark.asyncio
async def test_smart_connect_roaming_status_excludes_steering_policy() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.smart_connect_roaming_status()

    assert response["ok"] is True
    data = response["data"]
    assert data["smart_connect_enabled"] is True
    assert data["runtime_smart_connect_enabled"] is True
    assert data["steering_daemon_running"] is True
    assert data["roaming_daemon_running"] is True
    assert data["weak_rssi_difference_db"] == 10
    assert [r["roaming_rssi_threshold_dbm"] for r in data["radios"]] == [-70, -72, -68]
    serialized = str(response)
    assert "AA:BB:CC:DD:EE:99" not in serialized
    assert "steering_policy" not in serialized


@pytest.mark.asyncio
async def test_wireless_schedule_status_reports_sanitized_per_radio_schedule() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wireless_schedule_status()

    assert response["ok"] is True
    radios = response["data"]["radios"]
    assert response["data"]["radio_count"] == 3
    assert [radio["band_label"] for radio in radios] == [
        "2.4ghz", "5ghz-1", "5ghz-2"
    ]
    assert radios[0]["schedule_enabled"] is True
    assert radios[0]["configured_day_count"] == 5
    assert radios[0]["legacy_primary_window"] == {"start": "07:00", "end": "23:00"}
    assert radios[0]["legacy_secondary_window"] == {"start": "09:00", "end": "22:00"}
    assert radios[0]["v2_schedule_present"] is False
    assert radios[1]["schedule_enabled"] is False
    assert radios[2]["schedule_enabled"] is True
    assert radios[2]["configured_day_count"] == 4
    assert radios[2]["v2_schedule_present"] is True
    assert "opaque-v2-schedule-must-never-be-returned" not in str(response)


@pytest.mark.asyncio
async def test_wireless_advanced_reports_safe_per_radio_features() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.wireless_advanced()

    assert response["ok"] is True
    radios = response["data"]["radios"]
    assert response["data"]["radio_count"] == 3
    assert [r["band_label"] for r in radios] == ["2.4ghz", "5ghz-1", "5ghz-2"]
    assert radios[0]["wifi_6_enabled"] is False
    assert radios[1]["wifi_6_enabled"] is True
    assert radios[2]["ofdma_mode_code"] == 3
    assert radios[2]["airtime_fairness_enabled"] is True
    assert radios[1]["dfs_auto_channel_enabled"] is True
    assert [r["tx_power_percent"] for r in radios] == [100, 80, 90]
    serialized = str(response).lower()
    assert "wpa_psk" not in serialized
    assert "must-never-be-returned" not in serialized
    assert "bssid" not in serialized


@pytest.mark.asyncio
async def test_vlan_guest_status_redacts_raw_segmentation_policies() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.vlan_guest_status()

    assert response["ok"] is True
    assert response["data"] == {
        "vlan_enabled": True,
        "saved_vlan_rule_count": 2,
        "pvid_rule_count": 1,
        "guest_vlan_mode_enabled": True,
        "guest_vlan_bridge_rule_count": 2,
        "guest_vlan_profile_rule_count": 1,
        "wan_tagging_mode": "manual",
        "wan_vlan_tag_configured": True,
        "source": "ssh",
    }
    serialized = str(response)
    assert "private-segment" not in serialized
    assert "iot-segment" not in serialized
    assert "vlan_rulelist" not in serialized
    assert "wgn_brif_rulelist" not in serialized


@pytest.mark.asyncio
async def test_dual_wan_status_redacts_addresses_and_policy_payloads() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.dual_wan_status()

    assert response["ok"] is True
    assert response["data"] == {
        "primary_uplink_type": "wan",
        "secondary_uplink_type": "usb",
        "dual_wan_configured": True,
        "mode_code": "fo",
        "load_balance_ratio": "3:1",
        "policy_routing_enabled": True,
        "policy_rule_count": 2,
        "available_uplink_types": ["wan", "usb", "lan"],
        "active_unit": 0,
        "uplinks": [
            {
                "unit": 0,
                "type": "wan",
                "enabled": True,
                "protocol": "dhcp",
                "state_code": 2,
                "aux_state_code": 0,
                "sb_state_code": 0,
                "active": True,
            },
            {
                "unit": 1,
                "type": "usb",
                "enabled": True,
                "protocol": "dhcp",
                "state_code": 0,
                "aux_state_code": 0,
                "sb_state_code": 0,
                "active": False,
            },
        ],
        "source": "ssh",
    }
    serialized = str(response)
    assert "192.168.2.50" not in serialized
    assert "192.168.2.60" not in serialized
    assert "wans_routing_rulelist" not in serialized
    assert "wan0_ipaddr" not in serialized
    assert "wan0_gateway" not in serialized


@pytest.mark.asyncio
async def test_traffic_monitoring_status_exposes_only_sanitized_posture() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.traffic_monitoring_status()

    assert response["ok"] is True
    assert response["data"] == {
        "traffic_analyzer_enabled": True,
        "web_history_enabled": True,
        "app_analysis_enabled": True,
        "bandwidth_stats_enabled": True,
        "bandwidth_stats_process_running": True,
        "connection_stats_enabled": False,
        "connection_stats_process_running": False,
        "source": "ssh",
    }
    serialized = str(response).lower()
    assert "private-rstats-path" not in serialized
    assert "history_record" not in serialized
    assert "client" not in serialized


@pytest.mark.asyncio
async def test_auxiliary_services_status_separates_configured_and_runtime_state() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.auxiliary_services_status()

    assert response["ok"] is True
    assert response["data"] == {
        "ftp": {
            "enabled": True,
            "mode_code": 2,
            "wan_access_enabled": False,
            "tls_enabled": True,
            "process_running": True,
        },
        "media_server": {"enabled": True, "process_running": True},
        "webdav": {
            "enabled": False,
            "aidisk_enabled": False,
            "proxy_enabled": False,
        },
        "cloud_sync_enabled": False,
        "usb_modem": {
            "master_flag_enabled": True,
            "runtime_running": False,
            "wan_ready": False,
        },
        "usb_printer": {
            "enabled": False,
            "status_code": 0,
            "process_running": False,
        },
        "pptp_server": {"enabled": False, "process_running": False},
        "ipsec": {
            "server_enabled": True,
            "client_enabled": False,
            "process_running": True,
        },
        "source": "ssh",
    }
    serialized = str(response).lower()
    for marker in (
        "private-media-dir",
        "private-webdav-login",
        "private-modem-user",
        "private-modem-pass",
        "private-pptp-client",
        "private-ipsec-profile",
    ):
        assert marker not in serialized


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
async def test_firmware_update_status_decodes_safe_state_without_download_url() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.firmware_update_status()

    assert response["ok"] is True
    assert response["data"] == {
        "automatic_update_enabled": True,
        "beta_channel_enabled": False,
        "check_completed": True,
        "update_flag_code": 1,
        "update_available": True,
        "forced_update": False,
        "error_code": 0,
        "reported_version": "3004_388_99999-gabcdef0",
        "update_level_code": 2,
        "source": "ssh",
    }
    serialized = str(response)
    assert "private-download.example.invalid" not in serialized
    assert "token=secret" not in serialized


@pytest.mark.asyncio
async def test_admin_access_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.admin_access()

    assert response["ok"] is True
    assert response["data"]["ssh_admin"]["enabled"] is True
    assert len(response["data"]["processes"]) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sshd_enable", "expected_enabled"),
    [("0", False), ("1", True), ("2", True)],
)
async def test_admin_access_interprets_supported_ssh_modes(
    sshd_enable: str, expected_enabled: bool
) -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.values["sshd_enable"] = sshd_enable

    response = await service.admin_access()

    assert response["ok"] is True
    assert response["data"]["ssh_admin"]["enabled"] is expected_enabled
    assert response["data"]["ssh_admin"]["wan_enabled"] is False


@pytest.mark.asyncio
async def test_vpn_overview_tool_uses_ssh() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.vpn_overview()

    assert response["ok"] is True
    assert response["data"]["openvpn_server_enabled"] is True
    assert response["data"]["process_count"] == 1


@pytest.mark.asyncio
async def test_vpn_overview_detects_enabled_wireguard_client() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.values["vpnc_clientlist"] = ""
    MockSshClient.values["wgc1_enable"] = "1"

    response = await service.vpn_overview()

    assert response["ok"] is True
    assert response["data"]["vpn_client_profiles_configured"] is True


@pytest.mark.asyncio
async def test_vpn_client_status_reports_wireguard_runtime_health_without_peer_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = make_service(prefer_ssh=True)
    monkeypatch.setattr("asuswrt_mcp.service.time.time", lambda: 2_000)
    MockSshClient.commands.update(
        {
            "wg show interfaces 2>/dev/null || true": "wgc1",
            "wg show wgc1 latest-handshakes 2>/dev/null | awk '{if ($2 > latest) latest=$2} END {print latest+0}'": "1975",
            "wg show wgc1 transfer 2>/dev/null | awk '{rx+=$2; tx+=$3} END {print rx+0, tx+0}'": "4173900 3556928",
        }
    )

    response = await service.vpn_client_status()

    assert response["ok"] is True
    assert response["data"]["wireguard_clients"][0] == {"unit": 1, "enabled": True}
    assert response["data"]["wireguard_runtime"] == [
        {
            "unit": 1,
            "runtime_active": True,
            "latest_handshake_age_seconds": 25,
            "rx_bytes": 4_173_900,
            "tx_bytes": 3_556_928,
        }
    ]
    serialized = str(response).lower()
    for forbidden in ("peer", "endpoint", "public_key", "private_key", "address", "allowed_ips"):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_vpn_client_status_reports_sanitized_counts_and_units() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.vpn_client_status()

    assert response["ok"] is True
    assert response["data"] == {
        "master_enabled": True,
        "legacy_profile_count": 1,
        "wireguard_client_count": 2,
        "wireguard_enabled_count": 1,
        "wireguard_clients": [
            {"unit": 1, "enabled": True},
            {"unit": 2, "enabled": False},
        ],
        "wireguard_runtime": [
            {
                "unit": 1,
                "runtime_active": False,
                "latest_handshake_age_seconds": None,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
        ],
        "vpn_fusion_policy_record_count": 1,
        "source": "ssh",
    }
    serialized = str(response)
    for sensitive in (
        "legacy-private-endpoint",
        "legacy-private-user",
        "secret-profile",
        "AA:BB:CC:DD:EE:FF",
        "private-device-policy",
    ):
        assert sensitive not in serialized


@pytest.mark.asyncio
async def test_wan_watchdog_status_reports_probe_health_without_target() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.values.update(
        {
            "wandog_enable": "1",
            "wandog_interval": "3",
            "wandog_maxfail": "2",
            "wandog_delay": "0",
            "wandog_fb_count": "4",
            "wandog_fb_restart": "0",
            "dns_probe": "1",
            "dns_probe_timeout": "1",
            "dns_probe_host": "private-probe-target.example.invalid",
        }
    )
    MockSshClient.commands[
        "ps | grep -E 'wanduck' | grep -v grep || true"
    ] = "777 admin 1200 S wanduck"

    response = await service.wan_watchdog_status()

    assert response["ok"] is True
    assert response["data"] == {
        "enabled": True,
        "interval_value": 3,
        "max_failures": 2,
        "delay_value": 0,
        "fallback_count": 4,
        "fallback_restart_enabled": False,
        "dns_probe_enabled": True,
        "dns_probe_timeout_value": 1,
        "dns_probe_target_configured": True,
        "wanduck_running": True,
        "source": "ssh",
    }
    assert "private-probe-target.example.invalid" not in str(response)


@pytest.mark.asyncio
async def test_logging_status_redacts_remote_destination_and_log_path() -> None:
    service = make_service(prefer_ssh=True)

    response = await service.logging_status()

    assert response["ok"] is True
    assert response["data"] == {
        "syslogd_running": True,
        "klogd_running": True,
        "remote_syslog_configured": True,
        "remote_syslog_port": 514,
        "local_log_level_code": 6,
        "local_log_size_kb": 256,
        "persistent_logging_configured": True,
        "source": "ssh",
    }
    serialized = str(response)
    assert "192.168.2.200" not in serialized
    assert "/jffs/private-syslog-must-never-be-returned" not in serialized


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
async def test_usb_overview_includes_sanitized_disk_monitor_health() -> None:
    service = make_service(prefer_ssh=True)
    MockSshClient.values.update(
        {
            "diskmon_freq": "0",
            "diskmon_policy": "disk",
            "diskmon_status": "0",
            "diskmon_force_stop": "0",
            "pushnotify_diskmonitor": "1",
            "usb_idle_enable": "0",
            "usb_idle_timeout": "60",
            "diskmon_part": "/tmp/mnt/private-disk-path-must-never-be-returned",
        }
    )
    MockSshClient.commands[
        "ps | grep -E 'disk_monitor|diskmon' | grep -v grep || true"
    ] = "888 admin 1300 S disk_monitor"

    response = await service.usb_overview()

    assert response["ok"] is True
    assert response["data"]["disk_monitor"] == {
        "running": True,
        "status_code": 0,
        "policy": "disk",
        "frequency_value": 0,
        "force_stopped": False,
        "notification_enabled": True,
        "idle_enabled": False,
        "idle_timeout_value": 60,
    }
    assert "private-disk-path-must-never-be-returned" not in str(response)


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
async def test_mutations_enabled_still_requires_explicit_confirmation() -> None:
    service = make_service(prefer_ssh=True, allow_mutations=True)
    MockSshClient.writes = []

    with pytest.raises(Exception) as exc:
        await service.upnp(enabled=False, confirm=False, dry_run=False)

    assert getattr(exc.value, "code") == "confirmation_required"
    assert MockSshClient.writes == []
