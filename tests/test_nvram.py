from __future__ import annotations

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


def test_dhcp_staticlist_four_field_name_is_last() -> None:
    # 3004+/Merlin format <mac>ip>dns>name, incl. an entry with no name
    raw = "<AA:BB:CC:DD:EE:FF>192.168.50.20>>Printer<11:22:33:44:55:66>192.168.50.21>>"

    parsed = parse_dhcp_staticlist(raw)

    assert [(r.ip, r.name) for r in parsed] == [("192.168.50.20", "Printer"), ("192.168.50.21", "")]
