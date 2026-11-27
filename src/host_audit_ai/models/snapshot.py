"""Normalized host snapshot data contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HostMetadata(BaseModel):
    """Core operating system and hardware metadata."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    os_name: str = ""
    os_version: str = ""
    kernel_release: str = ""
    architecture: str = ""
    uptime_seconds: float | None = None


class UserAccount(BaseModel):
    """Local user account entry."""

    model_config = ConfigDict(extra="forbid")

    username: str
    uid: int
    gid: int
    home: str = ""
    shell: str = ""
    is_root_equivalent: bool = False
    locked: bool = False


class SudoRule(BaseModel):
    """Sudoers authorization rule."""

    model_config = ConfigDict(extra="forbid")

    user_or_group: str
    hosts: str = "ALL"
    run_as: str = "ALL"
    commands: list[str] = Field(default_factory=list)
    nopasswd: bool = False


class SshdConfig(BaseModel):
    """Effective SSH daemon configuration."""

    model_config = ConfigDict(extra="forbid")

    port: int = 22
    permit_root_login: str = "no"
    password_authentication: bool = False
    pubkey_authentication: bool = True
    raw_options: dict[str, str] = Field(default_factory=dict)


class ListeningSocket(BaseModel):
    """Active listening network socket."""

    model_config = ConfigDict(extra="forbid")

    protocol: str
    local_address: str
    local_port: int
    pid: int | None = None
    process_name: str | None = None
    interface: str | None = None


class ProcessEntry(BaseModel):
    """Running process snapshot entry."""

    model_config = ConfigDict(extra="forbid")

    pid: int
    ppid: int | None = None
    user: str = ""
    command: str = ""
    deleted_binary: bool = False


class ServiceUnit(BaseModel):
    """Systemd service unit state."""

    model_config = ConfigDict(extra="forbid")

    name: str
    load_state: str = ""
    active_state: str = ""
    sub_state: str = ""
    enabled: bool = False


class CronEntry(BaseModel):
    """Scheduled cron job entry."""

    model_config = ConfigDict(extra="forbid")

    schedule: str
    user: str = "root"
    command: str = ""
    source_file: str = ""


class SuidBinary(BaseModel):
    """SUID or SGID binary discovered on filesystem."""

    model_config = ConfigDict(extra="forbid")

    path: str
    owner: str = "root"
    permissions: str = ""
    known_gtfobins: bool = False


class FilePermCheck(BaseModel):
    """Critical or world-writable file permission check."""

    model_config = ConfigDict(extra="forbid")

    path: str
    permissions: str
    owner: str = ""
    group: str = ""
    is_world_writable: bool = False


class SysctlEntry(BaseModel):
    """Kernel runtime parameter entry."""

    model_config = ConfigDict(extra="forbid")

    key: str
    value: str


class FirewallState(BaseModel):
    """Firewall configuration and runtime status."""

    model_config = ConfigDict(extra="forbid")

    backend: str = "nftables"
    active: bool = False
    rules_summary: list[str] = Field(default_factory=list)
    docker_user_bypasses: bool = False


class PackageInfo(BaseModel):
    """Installed package information."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    architecture: str = ""
    source: str = ""


class ContainerInstance(BaseModel):
    """Runtime container instance details."""

    model_config = ConfigDict(extra="forbid")

    id: str = ""
    name: str = ""
    image: str = ""
    privileged: bool = False
    network_mode: str = ""
    pid_mode: str = ""
    ipc_mode: str = ""
    caps_add: list[str] = Field(default_factory=list)
    mounts: list[str] = Field(default_factory=list)
    status: str = ""


class ContainerState(BaseModel):
    """Container runtime discovery and running workload state."""

    model_config = ConfigDict(extra="forbid")

    socket_paths: list[str] = Field(default_factory=list)
    socket_permissions: list[FilePermCheck] = Field(default_factory=list)
    running_containers: list[ContainerInstance] = Field(default_factory=list)
    raw_inspect: list[dict[str, Any]] = Field(default_factory=list)


class IocSurface(BaseModel):
    """Indicators of compromise surface telemetry."""

    model_config = ConfigDict(extra="forbid")

    deleted_binary_processes: list[ProcessEntry] = Field(default_factory=list)
    ld_preload_contents: str | None = None
    temp_executables: list[str] = Field(default_factory=list)
    authorized_keys_files: list[FilePermCheck] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class AuthLogSummary(BaseModel):
    """Summary of recent authentication logs."""

    model_config = ConfigDict(extra="forbid")

    failed_logins: int = 0
    accepted_logins: int = 0
    root_logins: int = 0
    summary_window: str = ""


class ParseWarning(BaseModel):
    """Warning emitted while parsing collector output."""

    model_config = ConfigDict(extra="forbid")

    section_name: str
    message: str
    raw_line: str | None = None


class HostSnapshot(BaseModel):
    """Normalized structured snapshot of an audited host."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    collected_at: datetime
    degraded_mode: bool = False
    metadata: HostMetadata
    users: list[UserAccount] = Field(default_factory=list)
    sudo_rules: list[SudoRule] = Field(default_factory=list)
    sshd_config: SshdConfig | None = None
    listening_sockets: list[ListeningSocket] = Field(default_factory=list)
    processes: list[ProcessEntry] = Field(default_factory=list)
    services: list[ServiceUnit] = Field(default_factory=list)
    cron_entries: list[CronEntry] = Field(default_factory=list)
    suid_binaries: list[SuidBinary] = Field(default_factory=list)
    file_permissions: list[FilePermCheck] = Field(default_factory=list)
    sysctl_entries: list[SysctlEntry] = Field(default_factory=list)
    firewall: FirewallState | None = None
    packages: list[PackageInfo] = Field(default_factory=list)
    containers: ContainerState = Field(default_factory=ContainerState)
    ioc: IocSurface = Field(default_factory=IocSurface)
    capabilities: list[str] = Field(default_factory=list)
    auth_summary: AuthLogSummary | None = None
    parse_warnings: list[ParseWarning] = Field(default_factory=list)

    @field_validator("collected_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("collected_at must be a timezone-aware datetime")
        return v.astimezone(UTC)
