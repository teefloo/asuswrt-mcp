# Tool reference

`asuswrt-mcp` exposes **67 explicit MCP tools**: **55 read-only tools** and **12 management tools**. The server deliberately has no arbitrary SSH, arbitrary NVRAM, firmware flash/reset, bootloader, generic command or generic HTTP escape hatch.

## Management safety contract

Router mutations are disabled unless `ASUSWRT_ALLOW_MUTATIONS=true`. A real management change additionally requires `confirm=true`; `dry_run=true` returns the planned operation without changing router state. Mixed tools with a `list` action keep that action read-only. Inputs are validated and operations remain bounded to the allowlisted router behavior implemented by the tool.

Sensitive router material is minimized or redacted. In particular, tools do not expose Wi-Fi PSKs, VPN keys/peer identities/endpoints, DNS resolver values where only posture/counts are needed, or raw client-policy/rule payloads where a sanitized summary is sufficient.

## Tools

| Tool | Access | Inputs | Purpose | Side effects / guards |
| --- | --- | --- | --- | --- |
| `asuswrt_capabilities` | Read | — | Return server capabilities, guardrails, and safe settings. | None. Read-only and does not change router configuration. |
| `asuswrt_health` | Read | — | Fetch router identity and basic health data. | None. Read-only and does not change router configuration. |
| `asuswrt_ssh_diagnostics` | Read | — | Diagnose SSH TCP reachability, banner exchange, and authentication. | None. Read-only and does not change router configuration. |
| `asuswrt_identity` | Read | — | Fetch router model and firmware identity. | None. Read-only and does not change router configuration. |
| `asuswrt_system_stats` | Read | — | Fetch router uptime, load, and memory statistics. | None. Read-only and does not change router configuration. |
| `asuswrt_network_overview` | Read | — | Fetch LAN, WAN, and routing overview details. | None. Read-only and does not change router configuration. |
| `asuswrt_lan_details` | Read | — | Inspect LAN interface, addressing, and DHCP presence. | None. Read-only and does not change router configuration. |
| `asuswrt_wan_details` | Read | — | Inspect WAN protocol, IP, gateway, DNS, and interface details. | None. Read-only and does not change router configuration. |
| `asuswrt_dns_config` | Read | — | Inspect WAN and LAN DNS settings reported by NVRAM. | None. Read-only and does not change router configuration. |
| `asuswrt_dns_filter_status` | Read | — | Inspect DNS Filter/Director enablement and redacted configuration counts. | None. Read-only and does not change router configuration. |
| `asuswrt_dns_privacy_status` | Read | — | Inspect DNS-over-TLS and DNSSEC posture using redacted rule counts only. | None. Read-only and does not change router configuration. |
| `asuswrt_ipv6_status` | Read | — | Inspect IPv6 service, prefix, and router address details. | None. Read-only and does not change router configuration. |
| `asuswrt_dhcp_config` | Read | — | Inspect DHCP server pool settings and static reservations. | None. Read-only and does not change router configuration. |
| `asuswrt_time_sync` | Read | — | Inspect timezone and NTP synchronization settings. | None. Read-only and does not change router configuration. |
| `asuswrt_web_admin` | Read | — | Inspect web admin ports and related web processes. | None. Read-only and does not change router configuration. |
| `asuswrt_admin_access` | Read | — | Inspect web, SSH, and telnet administrative access settings. | None. Read-only and does not change router configuration. |
| `asuswrt_clients` | Read | — | List connected clients reported by the router. | None. Read-only and does not change router configuration. |
| `asuswrt_dhcp_leases` | Read | — | List active DHCP leases from dnsmasq. | None. Read-only and does not change router configuration. |
| `asuswrt_arp_neighbors` | Read | — | List ARP/IP neighbor entries known by the router. | None. Read-only and does not change router configuration. |
| `asuswrt_service_processes` | Read | — | List key allowlisted router processes and services. | None. Read-only and does not change router configuration. |
| `asuswrt_wireless_overview` | Read | — | Inspect wireless radios, SSIDs, and connected band counts. | None. Read-only and does not change router configuration. |
| `asuswrt_firewall_status` | Read | — | Inspect firewall enablement and safe protection settings. | None. Read-only and does not change router configuration. |
| `asuswrt_wireless_config` | Read | — | Inspect per-radio Wi-Fi channel and security metadata without credentials. | None. Read-only and does not change router configuration. |
| `asuswrt_qos_status` | Read | — | Inspect QoS enablement, configured mode, bandwidth, and redacted rule counts. | None. Read-only and does not change router configuration. |
| `asuswrt_aiprotection_status` | Read | — | Inspect AiProtection feature enablement and non-secret DPI signature versions. | None. Read-only and does not change router configuration. |
| `asuswrt_aimesh_status` | Read | — | Inspect AiMesh node counts and controller readiness without node identifiers. | None. Read-only and does not change router configuration. |
| `asuswrt_vlan_guest_status` | Read | — | Inspect VLAN and guest segmentation state using redacted counts only. | None. Read-only and does not change router configuration. |
| `asuswrt_dual_wan_status` | Read | — | Inspect Dual-WAN selection and uplink health without WAN addresses or policy payloads. | None. Read-only and does not change router configuration. |
| `asuswrt_wps_status` | Read | — | Inspect WPS enablement and per-radio status without PIN material. | None. Read-only and does not change router configuration. |
| `asuswrt_smart_connect_roaming_status` | Read | — | Inspect Smart Connect and roaming state without steering policies or client data. | None. Read-only and does not change router configuration. |
| `asuswrt_wireless_advanced` | Read | — | Inspect advanced per-radio Wi-Fi feature settings without credentials. | None. Read-only and does not change router configuration. |
| `asuswrt_wireless_schedule_status` | Read | — | Inspect sanitized per-radio Wi-Fi scheduling state without raw v2 schedule payloads. | None. Read-only and does not change router configuration. |
| `asuswrt_guest_networks` | Read | — | List guest Wi-Fi networks and LAN-access state. | None. Read-only and does not change router configuration. |
| `asuswrt_firmware_update_status` | Read | — | Inspect read-only firmware update status without checking, downloading, or flashing firmware. | None. Read-only and does not change router configuration. |
| `asuswrt_interface_stats` | Read | — | Inspect per-interface RX/TX counters from /proc/net/dev. | None. Read-only and does not change router configuration. |
| `asuswrt_open_ports` | Read | — | Inspect listening TCP/UDP sockets reported by netstat. | None. Read-only and does not change router configuration. |
| `asuswrt_kernel_modules` | Read | — | Inspect loaded kernel modules reported by lsmod. | None. Read-only and does not change router configuration. |
| `asuswrt_cron_jobs` | Read | — | Inspect scheduled cron jobs reported by cru. | None. Read-only and does not change router configuration. |
| `asuswrt_conntrack_status` | Read | — | Inspect conntrack table usage and limits. | None. Read-only and does not change router configuration. |
| `asuswrt_samba_status` | Read | — | Inspect Samba/SMB status and related processes. | None. Read-only and does not change router configuration. |
| `asuswrt_usb_overview` | Read | — | Inspect USB/storage partitions, mounts, filesystems, and sanitized disk-monitor health without device paths or identifiers. | None. Read-only and does not change router configuration. |
| `asuswrt_storage_usage` | Read | — | Inspect storage/filesystem usage reported by the router. | None. Read-only and does not change router configuration. |
| `asuswrt_mounts` | Read | — | Inspect mounted filesystems and mount options. | None. Read-only and does not change router configuration. |
| `asuswrt_partitions` | Read | — | Inspect block-device partitions reported by the router kernel. | None. Read-only and does not change router configuration. |
| `asuswrt_route_table` | Read | — | Inspect the router IPv4 route table. | None. Read-only and does not change router configuration. |
| `asuswrt_policy_routing` | Read | — | Inspect policy-routing rules reported by ip rule. | None. Read-only and does not change router configuration. |
| `asuswrt_vpn_overview` | Read | — | Inspect configured VPN modes and related processes. | None. Read-only and does not change router configuration. |
| `asuswrt_vpn_client_status` | Read | — | Inspect sanitized VPN client counts, WireGuard slot/runtime health, and VPN Fusion policy counts without credentials, endpoints, or peer details. | None. Read-only and does not change router configuration. |
| `asuswrt_wan_watchdog_status` | Read | — | Inspect WAN watchdog and DNS-probe posture without returning probe targets or sensitive connectivity details. | None. Read-only and does not change router configuration. |
| `asuswrt_logging_status` | Read | — | Inspect local and remote syslog posture without log destinations, paths, or process command details. | None. Read-only and does not change router configuration. |
| `asuswrt_traffic_monitoring_status` | Read | — | Inspect sanitized traffic analyzer, web-history, and rstats/cstats posture without traffic or history records. | None. Read-only and does not change router configuration. |
| `asuswrt_auxiliary_services_status` | Read | — | Inspect auxiliary router service posture without credentials, paths, clients, or raw service configuration. | None. Read-only and does not change router configuration. |
| `asuswrt_upnp_status` | Read | — | Inspect UPnP enablement and housekeeping settings. | None. Read-only and does not change router configuration. |
| `asuswrt_ddns_status` | Read | — | Inspect Dynamic DNS enablement and current provider settings. | None. Read-only and does not change router configuration. |
| `asuswrt_config_snapshot` | Read | — | Fetch a redacted read-only configuration snapshot. | None. Read-only and does not change router configuration. |
| `asuswrt_restart_service` | Management | `service: str`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Restart an allowlisted AsusWRT service. | Restarts one allowlisted router service. |
| `asuswrt_dhcp_server` | Management | `enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Enable or disable the DHCP server. | Changes DHCP-server enablement. |
| `asuswrt_upnp` | Management | `enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Enable or disable UPnP. | Changes UPnP enablement. |
| `asuswrt_guest_wifi` | Management | `band: Literal['2g', '5g', '5g2', '6g']`<br>`slot: int`<br>`enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Enable or disable a guest Wi-Fi slot. | Changes one bounded guest Wi-Fi slot. |
| `asuswrt_radio` | Management | `band: Literal['2g', '5g', '5g2', '6g']`<br>`enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Enable or disable a main Wi-Fi radio band. | Changes one main Wi-Fi radio state. |
| `asuswrt_guest_lan_access` | Management | `band: Literal['2g', '5g', '5g2', '6g']`<br>`slot: int`<br>`allow_lan: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Toggle LAN access for a guest Wi-Fi slot. | Changes LAN access for one guest Wi-Fi slot. |
| `asuswrt_port_forwarding` | Management | `action: Literal['list', 'enable', 'disable', 'add', 'remove']`<br>`name: str = ''`<br>`ip: str = ''`<br>`port: str = ''`<br>`protocol: Literal['TCP', 'UDP', 'BOTH'] = 'TCP'`<br>`port_external: str = ''`<br>`ip_external: str = ''`<br>`confirm: bool = False`<br>`dry_run: bool = False` | List, enable/disable, add, or remove port forwarding rules. | `list` is read-only; other actions change bounded port-forwarding state. |
| `asuswrt_vpn_server` | Management | `enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Enable or disable the OpenVPN server toggle. | Changes the OpenVPN server enable toggle. |
| `asuswrt_parental_access` | Management | `action: Literal['list', 'enable', 'disable', 'block', 'unblock', 'remove']`<br>`mac: str = ''`<br>`name: str = ''`<br>`confirm: bool = False`<br>`dry_run: bool = False` | List or manage AsusWRT parental access rules. | `list` is read-only; other actions change bounded parental-access rules. |
| `asuswrt_parental_block_all` | Management | `enabled: bool`<br>`confirm: bool = False`<br>`dry_run: bool = False` | Toggle parental-control block-all mode. | Changes parental-control block-all state. |
| `asuswrt_dhcp_reservation` | Management | `action: Literal['list', 'add', 'remove']`<br>`mac: str = ''`<br>`ip: str = ''`<br>`name: str = ''`<br>`confirm: bool = False`<br>`dry_run: bool = False` | List, add, or remove DHCP static reservations via SSH NVRAM. | `list` is read-only; other actions add/remove static DHCP reservations. |
