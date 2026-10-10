from __future__ import annotations

from asuswrt_mcp.server import _call


async def failing() -> dict:
    raise RuntimeError("boom")


async def test_call_converts_errors() -> None:
    response = await _call("test", failing())

    assert response["ok"] is False
    assert response["error"]["code"] == "unexpected_error"



def test_server_registers_extended_read_tools() -> None:
    from asuswrt_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools)
    assert {
        "asuswrt_dns_privacy_status",
        "asuswrt_vpn_client_status",
        "asuswrt_wan_watchdog_status",
        "asuswrt_firmware_update_status",
        "asuswrt_wireless_schedule_status",
        "asuswrt_logging_status",
        "asuswrt_traffic_monitoring_status",
        "asuswrt_auxiliary_services_status",
    } <= tool_names
    assert len(tool_names) == 66


def test_wan_watchdog_status_is_registered_and_declared() -> None:
    from asuswrt_mcp.server import mcp, router_service

    tool_name = "asuswrt_wan_watchdog_status"
    assert tool_name in mcp._tool_manager._tools
    assert tool_name in router_service.capabilities()["tools"]


def test_capabilities_inventory_matches_registered_tools() -> None:
    from asuswrt_mcp.server import mcp, router_service

    registered = set(mcp._tool_manager._tools)
    declared = set(router_service.capabilities()["tools"])
    assert declared == registered
