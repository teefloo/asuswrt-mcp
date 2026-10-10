"""Allowlisted SSH adapter for AsusWRT NVRAM and service operations."""

from __future__ import annotations

from contextlib import suppress
import socket
import shlex
from dataclasses import dataclass
import time
from typing import Any

import paramiko

from ..config import Settings
from ..errors import RouterOperationError
from ..validators import validate_nvram_key


@dataclass(slots=True)
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


class AsusRouterSshClient:
    """SSH client that exposes only narrowly scoped router primitives."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: paramiko.SSHClient | None = None

    @property
    def is_connected(self) -> bool:
        transport = self._client.get_transport() if self._client else None
        return bool(transport and transport.is_active())

    def connect(self) -> "AsusRouterSshClient":
        self._settings.require_ssh()
        key_filename = (
            str(self._settings.ssh_key_file)
            if self._settings.ssh_key_file is not None
            else None
        )
        connect_timeout = max(self._settings.timeout_seconds, 10.0)
        banner_timeout = max(self._settings.timeout_seconds * 2, 20.0)
        auth_timeout = max(self._settings.timeout_seconds * 2, 20.0)
        last_error: Exception | None = None

        for attempt in range(3):
            client = paramiko.SSHClient()
            if self._settings.ssh_strict_host_key:
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                client.connect(
                    hostname=self._settings.host or "",
                    port=self._settings.ssh_port,
                    username=self._settings.effective_ssh_username,
                    password=self._settings.effective_ssh_password,
                    key_filename=key_filename,
                    timeout=connect_timeout,
                    banner_timeout=banner_timeout,
                    auth_timeout=auth_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                self._client = client
                return self
            except (
                OSError,
                EOFError,
                TimeoutError,
                socket.timeout,
                paramiko.SSHException,
            ) as exc:
                last_error = exc
                with suppress(Exception):
                    client.close()
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue

        raise RouterOperationError(
            code="ssh_connect_failed",
            message="Unable to establish an SSH session to the router.",
            details={"reason": str(last_error) if last_error else "unknown"},
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "AsusRouterSshClient":
        return self.connect()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def client(self) -> paramiko.SSHClient:
        if self._client is None:
            raise RouterOperationError(
                code="ssh_not_connected",
                message="SSH router client is not connected.",
            )
        return self._client

    def _run_shell(self, command: str) -> CommandResult:
        _stdin, stdout, stderr = self.client.exec_command(
            command,
            timeout=self._settings.timeout_seconds,
        )
        exit_status = stdout.channel.recv_exit_status()
        result = CommandResult(
            command=command,
            stdout=stdout.read().decode(errors="replace").strip(),
            stderr=stderr.read().decode(errors="replace").strip(),
            exit_status=exit_status,
        )
        if result.exit_status != 0:
            raise RouterOperationError(
                code="ssh_command_failed",
                message="Allowlisted SSH command failed.",
                details={
                    "command": command,
                    "exit_status": result.exit_status,
                    "stderr": result.stderr,
                },
            )
        return result

    def run_command(self, command: str) -> CommandResult:
        """Run an internal allowlisted SSH command."""

        return self._run_shell(command)

    def get_nvram(self, key: str) -> str:
        safe_key = validate_nvram_key(key)
        return self._run_shell(f"nvram get {shlex.quote(safe_key)}").stdout

    def get_nvram_many(self, keys: list[str]) -> dict[str, str]:
        if not keys:
            return {}

        safe_keys = [validate_nvram_key(key) for key in keys]
        key_list = " ".join(shlex.quote(key) for key in safe_keys)
        result = self._run_shell(
            f"for k in {key_list}; do printf '%s=' \"$k\"; nvram get \"$k\"; printf '\\n'; done"
        )
        values = {key: "" for key in safe_keys}
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in values:
                values[key] = value
        return values

    def set_nvram(
        self,
        values: dict[str, str | int],
        *,
        commit: bool = True,
        service: str | None = None,
    ) -> CommandResult:
        commands = ["set -e"]
        for key, value in values.items():
            safe_key = validate_nvram_key(key)
            if "\x00" in str(value):
                raise RouterOperationError(
                    code="invalid_nvram_value",
                    message="NVRAM values cannot contain null bytes.",
                    details={"key": safe_key},
                )
            commands.append(f"nvram set {shlex.quote(f'{safe_key}={value}')}")
        if commit:
            commands.append("nvram commit")
        if service:
            commands.append(f"service {shlex.quote(service)}")
        return self._run_shell("; ".join(commands))

    def restart_service(self, service: str) -> CommandResult:
        return self._run_shell(f"service {shlex.quote(service)}")
