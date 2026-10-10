from __future__ import annotations

from asuswrt_mcp.errors import RouterOperationError

from asuswrt_mcp.nvram import (
    format_dhcp_staticlist,
    parse_dhcp_staticlist,
    parse_port_forwarding,
    remove_port_forwarding_rule,
    remove_dhcp_reservation,
    upsert_port_forwarding_rule,
    upsert_dhcp_reservation,
)


def test_dhcp_staticlist_roundtrip() -> None:
    raw = "<AA:BB:CC:DD:EE:FF>192.168.1.20>printer<11:22:33:44:55:66>192.168.1.21>nas"

    parsed = parse_dhcp_staticlist(raw)

    assert parsed[0].name == "printer"
    assert format_dhcp_staticlist(parsed) == raw


def test_upsert_dhcp_reservation_replaces_same_mac() -> None:
    raw = "<AA:BB:CC:DD:EE:FF>192.168.1.20>old"

    new_raw, changed, records = upsert_dhcp_reservation(
        raw,
        mac="aa:bb:cc:dd:ee:ff",
        ip="192.168.1.30",
        name="new",
    )

    assert changed is True
    assert len(records) == 1
    assert new_raw == "<AA:BB:CC:DD:EE:FF>192.168.1.30>new"


def test_remove_dhcp_reservation() -> None:
    raw = "<AA:BB:CC:DD:EE:FF>192.168.1.20>printer"

    new_raw, changed, records = remove_dhcp_reservation(
        raw,
        mac="AA:BB:CC:DD:EE:FF",
    )

    assert changed is True
    assert records == []
    assert new_raw == ""


def test_parse_port_forwarding() -> None:
    raw = "<Web>8443>192.168.1.10>443>TCP>>"

    parsed = parse_port_forwarding(raw)

    assert parsed[0].name == "Web"
    assert parsed[0].port_external == "8443"
    assert parsed[0].ip == "192.168.1.10"


def test_upsert_port_forwarding_rule() -> None:
    raw = "<Web>8443>192.168.1.10>443>TCP>>"

    new_raw, changed, rules = upsert_port_forwarding_rule(
        raw,
        name="SSH",
        ip="192.168.1.20",
        port="22",
        protocol="TCP",
        port_external="2222",
    )

    assert changed is True
    assert len(rules) == 2
    assert "<SSH>2222>192.168.1.20>22>TCP>>" in new_raw


def test_remove_port_forwarding_rule() -> None:
    raw = "<Web>8443>192.168.1.10>443>TCP>>"

    new_raw, changed, rules = remove_port_forwarding_rule(
        raw,
        ip="192.168.1.10",
        port_external="8443",
        protocol="TCP",
        port="443",
    )

    assert changed is True
    assert rules == []
    assert new_raw == ""


def test_parse_port_forwarding_preserves_existing_router_label_outside_write_allowlist() -> None:
    raw = "<PXPLAY 9295 UDP/TCP>9295>192.168.1.10>9295>BOTH>>"

    parsed = parse_port_forwarding(raw)

    assert parsed[0].name == "PXPLAY 9295 UDP/TCP"


def test_upsert_port_forwarding_preserves_existing_router_label_outside_write_allowlist() -> None:
    raw = "<PXPLAY 9295 UDP/TCP>9295>192.168.1.10>9295>BOTH>>"

    new_raw, changed, rules = upsert_port_forwarding_rule(
        raw,
        name="Web",
        ip="192.168.1.20",
        port="443",
        protocol="TCP",
        port_external="8443",
    )

    assert changed is True
    assert rules[0].name == "PXPLAY 9295 UDP/TCP"
    assert "<PXPLAY 9295 UDP/TCP>9295>192.168.1.10>9295>BOTH>>" in new_raw


def test_parse_dhcp_staticlist_preserves_existing_router_label_outside_write_allowlist() -> None:
    raw = "<AA:BB:CC:DD:EE:FF>192.168.1.20>Printer/Office"

    parsed = parse_dhcp_staticlist(raw)

    assert parsed[0].name == "Printer/Office"



def test_new_port_forwarding_label_still_uses_strict_write_validation() -> None:
    try:
        upsert_port_forwarding_rule(
            "",
            name="New/Rule",
            ip="192.168.1.20",
            port="443",
            protocol="TCP",
            port_external="8443",
        )
    except RouterOperationError as exc:
        assert exc.code == "invalid_label"
    else:
        raise AssertionError("new port-forward labels outside the write allowlist must be rejected")


def test_new_dhcp_label_still_uses_strict_write_validation() -> None:
    try:
        upsert_dhcp_reservation(
            "",
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.20",
            name="New/Reservation",
        )
    except RouterOperationError as exc:
        assert exc.code == "invalid_label"
    else:
        raise AssertionError("new DHCP labels outside the write allowlist must be rejected")
