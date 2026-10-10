"""Safe parsers/formatters for selected AsusWRT NVRAM values."""

from __future__ import annotations

from dataclasses import dataclass

from .validators import (
    normalize_mac,
    validate_ip,
    validate_label,
    validate_port_range,
)


@dataclass(frozen=True, slots=True)
class DhcpReservation:
    mac: str
    ip: str
    name: str = ""


@dataclass(frozen=True, slots=True)
class PortForwardRule:
    name: str
    port_external: str
    ip: str
    port: str
    protocol: str
    ip_external: str = ""


def parse_angle_records(value: str, fields: int) -> list[list[str]]:
    """Parse AsusWRT strings like <a>b>c><d>e>f> into records."""

    records: list[list[str]] = []
    for chunk in value.split("<"):
        if not chunk:
            continue
        parts = chunk.rstrip(">").split(">")
        while len(parts) < fields:
            parts.append("")
        records.append(parts[:fields])
    return records


def _observed_label(value: str) -> str:
    """Preserve router-supplied labels; write paths validate new labels separately."""

    return value.strip()


def parse_dhcp_staticlist(value: str) -> list[DhcpReservation]:
    records = []
    for mac, ip, name in parse_angle_records(value, 3):
        if mac and ip:
            records.append(
                DhcpReservation(
                    mac=normalize_mac(mac),
                    ip=validate_ip(ip),
                    name=_observed_label(name),
                )
            )
    return records


def format_dhcp_staticlist(records: list[DhcpReservation]) -> str:
    return "".join(f"<{item.mac}>{item.ip}>{item.name}" for item in records)


def upsert_dhcp_reservation(
    current: str,
    *,
    mac: str,
    ip: str,
    name: str = "",
) -> tuple[str, bool, list[DhcpReservation]]:
    safe_mac = normalize_mac(mac)
    safe_ip = validate_ip(ip)
    safe_name = validate_label(name, "name")
    records = [item for item in parse_dhcp_staticlist(current) if item.mac != safe_mac]
    new_record = DhcpReservation(safe_mac, safe_ip, safe_name)
    changed = new_record not in parse_dhcp_staticlist(current)
    records.append(new_record)
    return format_dhcp_staticlist(records), changed, records


def remove_dhcp_reservation(
    current: str,
    *,
    mac: str,
) -> tuple[str, bool, list[DhcpReservation]]:
    safe_mac = normalize_mac(mac)
    existing = parse_dhcp_staticlist(current)
    records = [item for item in existing if item.mac != safe_mac]
    return format_dhcp_staticlist(records), len(records) != len(existing), records


def parse_port_forwarding(value: str) -> list[PortForwardRule]:
    records = []
    for name, port_external, ip, port, protocol, ip_external in parse_angle_records(
        value, 6
    ):
        if ip and port_external and protocol:
            records.append(
                PortForwardRule(
                    name=_observed_label(name),
                    port_external=validate_port_range(port_external, "port_external"),
                    ip=validate_ip(ip),
                    port=validate_port_range(port or port_external, "port"),
                    protocol=protocol.upper(),
                    ip_external=validate_ip(ip_external) if ip_external else "",
                )
            )
    return records


def format_port_forwarding(records: list[PortForwardRule]) -> str:
    return "".join(
        (
            f"<{item.name}>{item.port_external}>{item.ip}>"
            f"{item.port}>{item.protocol}>{item.ip_external}>"
        )
        for item in records
    )


def upsert_port_forwarding_rule(
    current: str,
    *,
    name: str,
    ip: str,
    port: str,
    protocol: str,
    port_external: str,
    ip_external: str = "",
) -> tuple[str, bool, list[PortForwardRule]]:
    new_rule = PortForwardRule(
        name=validate_label(name, "name"),
        port_external=validate_port_range(port_external, "port_external"),
        ip=validate_ip(ip),
        port=validate_port_range(port, "port"),
        protocol=protocol.upper(),
        ip_external=validate_ip(ip_external) if ip_external else "",
    )
    rules = parse_port_forwarding(current)
    if new_rule in rules:
        return format_port_forwarding(rules), False, rules
    rules.append(new_rule)
    return format_port_forwarding(rules), True, rules


def remove_port_forwarding_rule(
    current: str,
    *,
    ip: str,
    port_external: str,
    protocol: str,
    port: str | None = None,
    ip_external: str | None = None,
) -> tuple[str, bool, list[PortForwardRule]]:
    safe_ip = validate_ip(ip)
    safe_port_external = validate_port_range(port_external, "port_external")
    safe_protocol = protocol.upper()
    safe_port = validate_port_range(port, "port") if port else None
    safe_ip_external = validate_ip(ip_external) if ip_external else None

    original = parse_port_forwarding(current)
    filtered = [
        rule
        for rule in original
        if not (
            rule.ip == safe_ip
            and rule.port_external == safe_port_external
            and rule.protocol == safe_protocol
            and (safe_port is None or rule.port == safe_port)
            and (safe_ip_external is None or rule.ip_external == safe_ip_external)
        )
    ]
    return (
        format_port_forwarding(filtered),
        len(filtered) != len(original),
        filtered,
    )
