# AsusWRT MCP Server

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Project Status: Active](https://img.shields.io/badge/status-active-green.svg)](https://github.com/Teeflo/asuswrt-mcp)

mcp-name: io.github.teefloo/asuswrt-mcp

Model Context Protocol (MCP) server for secure, controlled administration of AsusWRT and AsusWRT-Merlin routers via SSH.

## Overview

This MCP server provides AI assistants (like Claude, Cursor, etc.) with a safe interface to monitor and manage AsusWRT routers. It operates exclusively over SSH using allowlisted operations—no arbitrary command execution, no firmware modifications, and no factory resets.

## Features

### Read-Only Monitoring (42 tools)

| Category | Tools |
|----------|-------|
| **Identity & Health** | Router model, firmware version, uptime, load, memory |
| **Network** | LAN/WAN details, DNS config, IPv6 status, routing table |
| **Clients** | Connected clients, DHCP leases, ARP neighbors |
| **Wireless** | Radio status, SSIDs, guest networks, client counts per band |
| **Services** | Running processes, open ports, cron jobs |
| **Storage** | USB devices, mounts, partitions, filesystem usage |
| **Security** | UPnP, DDNS, Samba status, conntrack usage |
| **VPN** | OpenVPN server, WireGuard, VPN client profiles |
| **Administration** | Web admin ports, SSH/telnet access settings |
| **Diagnostics** | SSH TCP/banner/auth diagnostics, config snapshot |

### Mutation Tools (with safety guards)

All mutation tools require:
- `confirm: true` parameter
- `ASUSWRT_ALLOW_MUTATIONS=true` environment variable
- Support for `dry_run: true` to preview changes

| Tool | Description |
|------|-------------|
| `asuswrt_restart_service` | Restart allowlisted services (httpd, firewall, wireless, dnsmasq, etc.) |
| `asuswrt_dhcp_server` | Enable/disable DHCP server |
| `asuswrt_upnp` | Enable/disable UPnP |
| `asuswrt_radio` | Enable/disable Wi-Fi radio bands |
| `asuswrt_guest_wifi` | Enable/disable guest Wi-Fi |
| `asuswrt_guest_lan_access` | Toggle LAN access for guest Wi-Fi |
| `asuswrt_port_forwarding` | List, add, remove, enable/disable port forwarding rules |
| `asuswrt_vpn_server` | Enable/disable OpenVPN server |
| `asuswrt_parental_access` | List, block, unblock, remove parental control rules |
| `asuswrt_parental_block_all` | Toggle block-all mode |
| `asuswrt_dhcp_reservation` | List, add, remove DHCP static reservations |

### Safety Model

- **No arbitrary SSH**: Only allowlisted commands are executed via NVRAM and service calls
- **No firmware operations**: No flash, reset, or bootloader access
- **Secret redaction**: Passwords and sensitive data are never exposed in tool responses
- **Dry-run support**: Every mutation can be previewed before applying
- **Confirmation required**: Mutations require explicit `confirm=True`
- **SSH-only transport**: No exposure of the router's web API

## Prerequisites

- Python 3.11+
- An AsusWRT or AsusWRT-Merlin router with SSH access enabled
- The router SSH host key independently verified and present in the current account's SSH known_hosts file
- Network connectivity from the MCP client to the router

## Installation

### 1. Clone and setup

```bash
git clone https://github.com/Teeflo/asuswrt-mcp.git
cd asuswrt-mcp

# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install dependencies
pip install -e .
```

### 2. Configure environment

```bash
# Copy example configuration
cp .env.example .env

# Edit with your router credentials
# Use your favorite editor:
notepad .env        # Windows
nano .env           # Linux/macOS
```

**SSH host-key trust:** Before the first connection, verify the router's
SSH host-key fingerprint using a separate trusted channel, and install
the matching public host key into the operating account's SSH
known_hosts file. Unknown or changed keys are rejected; the previous
ASUSWRT_SSH_STRICT_HOST_KEY=false setting no longer permits bypassing
host identity verification. Existing installations that relied on
automatic trust will need one-time known_hosts preparation.

### 3. Configure `.env`

```env
# Required: Router connection
ASUSWRT_HOST=192.168.1.1
ASUSWRT_SSH_USERNAME=admin
ASUSWRT_SSH_PASSWORD=your_password

# Optional: SSH key authentication
# ASUSWRT_SSH_KEY_FILE=~/.ssh/id_rsa

# Optional: Enable mutations (disabled by default)
# ASUSWRT_ALLOW_MUTATIONS=true

# Optional: Connection settings
# ASUSWRT_SSH_PORT=22
# ASUSWRT_TIMEOUT_SECONDS=10
```

## Usage

### Run the MCP server

```bash
# Standard stdio mode
python -m asuswrt_mcp.server

# Or use the entry point
asuswrt-mcp
```

### Configure in Claude Desktop / Cursor

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "asuswrt-mcp": {
      "command": "C:\\path\\to\\asuswrt-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "asuswrt_mcp.server"],
      "env": {
        "ASUSWRT_HOST": "192.168.1.1",
        "ASUSWRT_SSH_USERNAME": "admin",
        "ASUSWRT_SSH_PASSWORD": "your_password"
      }
    }
  }
}
```

### Using with npx Inspector (development)

```bash
npx @modelcontextprotocol/inspector python -m asuswrt_mcp.server
```

## Development

### Run tests

```bash
pip install -e ".[dev]"
pytest
```

### Run with live router integration tests

```bash
ASUSWRT_TEST_ROUTER=1 pytest
```

## Project Structure

```
asuswrt-mcp/
├── src/asuswrt_mcp/
│   ├── server.py          # FastMCP entrypoint & tool definitions
│   ├── service.py         # Business logic & router operations
│   ├── config.py          # Settings management
│   ├── clients/
│   │   └── ssh.py         # SSH client wrapper
│   ├── nvram.py           # NVRAM parsing utilities
│   ├── ssh_parsers.py     # Output parsers for SSH commands
│   ├── security.py        # Mutation guards & redaction
│   ├── validators.py      # Input validation
│   ├── responses.py       # Tool response formatting
│   ├── errors.py          # Custom exceptions
│   └── serialization.py   # Safe serialization
├── tests/                 # Test suite (69 tests)
├── .env.example           # Example configuration
├── pyproject.toml         # Project metadata
└── README.md              # This file
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [asusrouter](https://pypi.org/project/asusrouter/) for the underlying Python library
- [MCP](https://modelcontextprotocol.io/) for the protocol specification
- [AsusWRT-Merlin](https://asuswrt-merlin.net/) for the firmware