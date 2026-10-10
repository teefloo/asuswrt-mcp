"""FastMCP entrypoint."""

from __future__ import annotations

import json
from typing import Literal

from mcp.server.fastmcp import FastMCP

from .responses import tool_error
from .service import RouterService

mcp = FastMCP("asuswrt-mcp")
router_service = RouterService()


async def _call(operation: str, awaitable, *, dry_run: bool = False):
    try:
        return await awaitable
    except Exception as exc:  # noqa: BLE001 - convert all tool failures
        return tool_error(operation, exc, dry_run=dry_run)


@mcp.tool(description="Return server capabilities, guardrails, and safe settings.")
async def asuswrt_capabilities() -> dict:
    return router_service.capabilities()


@mcp.tool(description="Fetch router identity and basic health data.")
async def asuswrt_health() -> dict:
    return await _call("asuswrt_health", router_service.health())


@mcp.tool(description="Diagnose SSH TCP reachability, banner exchange, and authentication.")
async def asuswrt_ssh_diagnostics() -> dict:
    return await _call("asuswrt_ssh_diagnostics", router_service.ssh_diagnostics())


@mcp.tool(description="Fetch router model and firmware identity.")
async def asuswrt_identity() -> dict:
    return await _call("asuswrt_identity", router_service.identity())


@mcp.tool(description="Fetch router uptime, load, and memory statistics.")
async def asuswrt_system_stats() -> dict:
    return await _call("asuswrt_system_stats", router_service.system_stats())


@mcp.tool(description="Fetch LAN, WAN, and routing overview details.")
async def asuswrt_network_overview() -> dict:
    return await _call(
        "asuswrt_network_overview",
        router_service.network_overview(),
    )


@mcp.tool(description="Inspect LAN interface, addressing, and DHCP presence.")
async def asuswrt_lan_details() -> dict:
    return await _call("asuswrt_lan_details", router_service.lan_details())


@mcp.tool(description="Inspect WAN protocol, IP, gateway, DNS, and interface details.")
async def asuswrt_wan_details() -> dict:
    return await _call("asuswrt_wan_details", router_service.wan_details())


@mcp.tool(description="Inspect WAN and LAN DNS settings reported by NVRAM.")
async def asuswrt_dns_config() -> dict:
    return await _call("asuswrt_dns_config", router_service.dns_config())


@mcp.tool(description="Inspect IPv6 service, prefix, and router address details.")
async def asuswrt_ipv6_status() -> dict:
    return await _call("asuswrt_ipv6_status", router_service.ipv6_status())


@mcp.tool(description="Inspect DHCP server pool settings and static reservations.")
async def asuswrt_dhcp_config() -> dict:
    return await _call("asuswrt_dhcp_config", router_service.dhcp_config())


@mcp.tool(description="Inspect timezone and NTP synchronization settings.")
async def asuswrt_time_sync() -> dict:
    return await _call("asuswrt_time_sync", router_service.time_sync())


@mcp.tool(description="Inspect web admin ports and related web processes.")
async def asuswrt_web_admin() -> dict:
    return await _call("asuswrt_web_admin", router_service.web_admin())


@mcp.tool(description="Inspect web, SSH, and telnet administrative access settings.")
async def asuswrt_admin_access() -> dict:
    return await _call("asuswrt_admin_access", router_service.admin_access())


@mcp.tool(description="List connected clients reported by the router.")
async def asuswrt_clients() -> dict:
    return await _call("asuswrt_clients", router_service.clients())


@mcp.tool(description="List active DHCP leases from dnsmasq.")
async def asuswrt_dhcp_leases() -> dict:
    return await _call("asuswrt_dhcp_leases", router_service.dhcp_leases())


@mcp.tool(description="List ARP/IP neighbor entries known by the router.")
async def asuswrt_arp_neighbors() -> dict:
    return await _call("asuswrt_arp_neighbors", router_service.arp_neighbors())


@mcp.tool(description="List key allowlisted router processes and services.")
async def asuswrt_service_processes() -> dict:
    return await _call(
        "asuswrt_service_processes",
        router_service.service_processes(),
    )


@mcp.tool(description="Inspect wireless radios, SSIDs, and connected band counts.")
async def asuswrt_wireless_overview() -> dict:
    return await _call(
        "asuswrt_wireless_overview",
        router_service.wireless_overview(),
    )


@mcp.tool(description="List guest Wi-Fi networks and LAN-access state.")
async def asuswrt_guest_networks() -> dict:
    return await _call("asuswrt_guest_networks", router_service.guest_networks())


@mcp.tool(description="Inspect per-interface RX/TX counters from /proc/net/dev.")
async def asuswrt_interface_stats() -> dict:
    return await _call("asuswrt_interface_stats", router_service.interface_stats())


@mcp.tool(description="Inspect listening TCP/UDP sockets reported by netstat.")
async def asuswrt_open_ports() -> dict:
    return await _call("asuswrt_open_ports", router_service.open_ports())


@mcp.tool(description="Inspect loaded kernel modules reported by lsmod.")
async def asuswrt_kernel_modules() -> dict:
    return await _call("asuswrt_kernel_modules", router_service.kernel_modules())


@mcp.tool(description="Inspect scheduled cron jobs reported by cru.")
async def asuswrt_cron_jobs() -> dict:
    return await _call("asuswrt_cron_jobs", router_service.cron_jobs())


@mcp.tool(description="Inspect conntrack table usage and limits.")
async def asuswrt_conntrack_status() -> dict:
    return await _call(
        "asuswrt_conntrack_status",
        router_service.conntrack_status(),
    )


@mcp.tool(description="Inspect Samba/SMB status and related processes.")
async def asuswrt_samba_status() -> dict:
    return await _call("asuswrt_samba_status", router_service.samba_status())


@mcp.tool(description="Inspect USB/storage-related partitions, mounts, and filesystems.")
async def asuswrt_usb_overview() -> dict:
    return await _call("asuswrt_usb_overview", router_service.usb_overview())


@mcp.tool(description="Inspect storage/filesystem usage reported by the router.")
async def asuswrt_storage_usage() -> dict:
    return await _call("asuswrt_storage_usage", router_service.storage_usage())


@mcp.tool(description="Inspect mounted filesystems and mount options.")
async def asuswrt_mounts() -> dict:
    return await _call("asuswrt_mounts", router_service.mounts())


@mcp.tool(description="Inspect block-device partitions reported by the router kernel.")
async def asuswrt_partitions() -> dict:
    return await _call("asuswrt_partitions", router_service.partitions())


@mcp.tool(description="Inspect the router IPv4 route table.")
async def asuswrt_route_table() -> dict:
    return await _call("asuswrt_route_table", router_service.route_table())


@mcp.tool(description="Inspect policy-routing rules reported by ip rule.")
async def asuswrt_policy_routing() -> dict:
    return await _call("asuswrt_policy_routing", router_service.policy_routing())


@mcp.tool(description="Inspect configured VPN modes and related processes.")
async def asuswrt_vpn_overview() -> dict:
    return await _call("asuswrt_vpn_overview", router_service.vpn_overview())


@mcp.tool(description="Inspect UPnP enablement and housekeeping settings.")
async def asuswrt_upnp_status() -> dict:
    return await _call("asuswrt_upnp_status", router_service.upnp_status())


@mcp.tool(description="Inspect Dynamic DNS enablement and current provider settings.")
async def asuswrt_ddns_status() -> dict:
    return await _call("asuswrt_ddns_status", router_service.ddns_status())


@mcp.tool(description="Fetch a redacted read-only configuration snapshot.")
async def asuswrt_config_snapshot() -> dict:
    return await _call("asuswrt_config_snapshot", router_service.config_snapshot())


@mcp.tool(description="Configure remote UDP syslog to one private IPv4 destination, or disable it, with confirmation and dry-run safeguards.")
async def asuswrt_remote_syslog(
    enabled: bool,
    destination: str = "",
    port: int = 514,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_remote_syslog",
        router_service.remote_syslog(
            enabled=enabled, destination=destination, port=port,
            confirm=confirm, dry_run=dry_run,
        ),
        dry_run=dry_run,
    )

@mcp.tool(description="Restart an allowlisted AsusWRT service.")
async def asuswrt_restart_service(
    service: str,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_restart_service",
        router_service.restart_service(
            service=service,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Enable or disable the DHCP server.")
async def asuswrt_dhcp_server(
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_dhcp_server",
        router_service.dhcp_server(
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Enable or disable UPnP.")
async def asuswrt_upnp(
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_upnp",
        router_service.upnp(
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Enable or disable a guest Wi-Fi slot.")
async def asuswrt_guest_wifi(
    band: Literal["2g", "5g", "5g2", "6g"],
    slot: int,
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_guest_wifi",
        router_service.guest_wifi(
            band=band,
            slot=slot,
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Enable or disable a main Wi-Fi radio band.")
async def asuswrt_radio(
    band: Literal["2g", "5g", "5g2", "6g"],
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_radio",
        router_service.radio(
            band=band,
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Toggle LAN access for a guest Wi-Fi slot.")
async def asuswrt_guest_lan_access(
    band: Literal["2g", "5g", "5g2", "6g"],
    slot: int,
    allow_lan: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_guest_lan_access",
        router_service.guest_lan_access(
            band=band,
            slot=slot,
            allow_lan=allow_lan,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="List, enable/disable, add, or remove port forwarding rules.")
async def asuswrt_port_forwarding(
    action: Literal["list", "enable", "disable", "add", "remove"],
    name: str = "",
    ip: str = "",
    port: str = "",
    protocol: Literal["TCP", "UDP", "BOTH"] = "TCP",
    port_external: str = "",
    ip_external: str = "",
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_port_forwarding",
        router_service.port_forwarding(
            action=action,
            name=name,
            ip=ip,
            port=port,
            protocol=protocol,
            port_external=port_external,
            ip_external=ip_external,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Enable or disable the OpenVPN server toggle.")
async def asuswrt_vpn_server(
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_vpn_server",
        router_service.vpn_server(
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="List or manage AsusWRT parental access rules.")
async def asuswrt_parental_access(
    action: Literal["list", "enable", "disable", "block", "unblock", "remove"],
    mac: str = "",
    name: str = "",
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_parental_access",
        router_service.parental_access(
            action=action,
            mac=mac,
            name=name,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="Toggle parental-control block-all mode.")
async def asuswrt_parental_block_all(
    enabled: bool,
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_parental_block_all",
        router_service.parental_block_all(
            enabled=enabled,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.tool(description="List, add, or remove DHCP static reservations via SSH NVRAM.")
async def asuswrt_dhcp_reservation(
    action: Literal["list", "add", "remove"],
    mac: str = "",
    ip: str = "",
    name: str = "",
    confirm: bool = False,
    dry_run: bool = False,
) -> dict:
    return await _call(
        "asuswrt_dhcp_reservation",
        router_service.dhcp_reservation(
            action=action,
            mac=mac,
            ip=ip,
            name=name,
            confirm=confirm,
            dry_run=dry_run,
        ),
        dry_run=dry_run,
    )


@mcp.resource(
    "asuswrt://capabilities",
    name="AsusWRT MCP capabilities",
    mime_type="application/json",
)
def capabilities_resource() -> str:
    return json.dumps(router_service.capabilities(), indent=2, sort_keys=True)


@mcp.resource(
    "asuswrt://last-snapshot",
    name="Last redacted AsusWRT snapshot",
    mime_type="application/json",
)
def last_snapshot_resource() -> str:
    return json.dumps(router_service.last_snapshot, indent=2, sort_keys=True)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
