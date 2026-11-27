"""Read-only parameterized audit-ssh MCP server (stdio transport)."""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path
from typing import Any, Literal

from host_audit_ai.collectors.transport import SSHTarget
from host_audit_ai.mcp_servers.audit_ssh_core import AuditSSHClient

READ_ONLY_TOOL_NAMES = (
    "ping_target",
    "inspect_unit",
    "read_config_snippet",
    "check_binary_perms",
    "check_listening_process",
    "check_package_version",
)


def _require_fastmcp() -> Any:
    try:
        mod = importlib.import_module("mcp.server.fastmcp")
        return mod.FastMCP
    except ImportError as e:
        raise ImportError(
            "The 'mcp' package is required to run audit-ssh MCP server. "
            'Install it via: uv pip install "host-audit-ai[crew]"'
        ) from e


def _client_from_env() -> AuditSSHClient:
    target_uri = os.environ.get("HOST_AUDIT_SSH_TARGET", "").strip()
    identity_str = os.environ.get("HOST_AUDIT_SSH_IDENTITY", "").strip()
    policy_raw = os.environ.get("HOST_AUDIT_SSH_HOST_KEY_POLICY", "strict").strip().lower()

    if not target_uri:
        raise ValueError("HOST_AUDIT_SSH_TARGET environment variable is required")
    if not identity_str:
        raise ValueError("HOST_AUDIT_SSH_IDENTITY environment variable is required")

    target = (
        SSHTarget.from_uri(target_uri)
        if target_uri.startswith("ssh://")
        else SSHTarget.from_uri(f"ssh://{target_uri}")
    )
    policy: Literal["strict", "accept-new"] = (
        "accept-new" if policy_raw == "accept-new" else "strict"
    )
    return AuditSSHClient(
        target=target,
        identity_file=Path(identity_str),
        known_hosts_policy=policy,
    )


def create_audit_ssh_server(client: AuditSSHClient | None = None) -> Any:
    """Create and configure the read-only FastMCP('audit-ssh') server instance."""
    fastmcp_cls = _require_fastmcp()
    ssh_client = client if client is not None else _client_from_env()
    mcp = fastmcp_cls("audit-ssh")

    def ping_target() -> dict[str, Any]:
        """Verify forced-command SSH connectivity to host-audit-wrapper."""
        return ssh_client.ping().model_dump()

    def inspect_unit(unit_name: str) -> dict[str, Any]:
        """Inspect systemd unit status and definition (read-only)."""
        try:
            return ssh_client.inspect_unit(unit_name).model_dump()
        except ValueError as e:
            return {"ok": False, "verb": "inspect-unit", "error": str(e)}

    def read_config_snippet(path: str, start_line: int = 1, max_lines: int = 80) -> dict[str, Any]:
        """Read a bounded slice from an allowlisted host configuration file."""
        try:
            return ssh_client.read_config_snippet(
                path, start_line=start_line, max_lines=max_lines
            ).model_dump()
        except ValueError as e:
            return {"ok": False, "verb": "read-config", "error": str(e)}

    def check_binary_perms(path: str) -> dict[str, Any]:
        """Check realpath, permissions, ownership, and capabilities for a binary."""
        try:
            return ssh_client.check_binary_perms(path).model_dump()
        except ValueError as e:
            return {"ok": False, "verb": "check-binary", "error": str(e)}

    def check_listening_process(port: int, proto: str = "tcp") -> dict[str, Any]:
        """Check listening socket process details for a port and protocol."""
        try:
            return ssh_client.check_listening_process(port, proto=proto).model_dump()
        except ValueError as e:
            return {"ok": False, "verb": "check-port", "error": str(e)}

    def check_package_version(package_name: str) -> dict[str, Any]:
        """Query installed version of a package on the target host."""
        try:
            return ssh_client.check_package_version(package_name).model_dump()
        except ValueError as e:
            return {"ok": False, "verb": "check-pkg", "error": str(e)}

    register_tool = mcp.tool()
    for fn in (
        ping_target,
        inspect_unit,
        read_config_snippet,
        check_binary_perms,
        check_listening_process,
        check_package_version,
    ):
        register_tool(fn)

    return mcp


def main(argv: list[str] | None = None) -> int:
    """Entrypoint for `python -m host_audit_ai.mcp_servers.audit_ssh`."""
    parser = argparse.ArgumentParser(description="Read-only audit-ssh MCP server")
    parser.add_argument("--target", default=os.environ.get("HOST_AUDIT_SSH_TARGET", ""))
    parser.add_argument("--identity", default=os.environ.get("HOST_AUDIT_SSH_IDENTITY", ""))
    parser.add_argument(
        "--host-key-policy",
        choices=("strict", "accept-new"),
        default=os.environ.get("HOST_AUDIT_SSH_HOST_KEY_POLICY", "strict"),
    )
    args = parser.parse_args(argv)

    if args.target:
        os.environ["HOST_AUDIT_SSH_TARGET"] = args.target
    if args.identity:
        os.environ["HOST_AUDIT_SSH_IDENTITY"] = args.identity
    if args.host_key_policy:
        os.environ["HOST_AUDIT_SSH_HOST_KEY_POLICY"] = args.host_key_policy

    try:
        server = create_audit_ssh_server()
    except (ImportError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
