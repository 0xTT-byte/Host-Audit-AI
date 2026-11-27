"""Strictly separated, scoped MCP adapter factories for air-gapped agents.

Agent 1 (Host Inspector) receives ONLY ssh_mcp_adapter().
Agent 2 (CVE Researcher) receives ONLY web_mcp_adapter().
No combined SSH + Web factory is ever exposed.
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from host_audit_ai.collectors.transport import SSHTarget


@dataclass(frozen=True)
class SSHServerConfig:
    """Validated connection parameters for launching the isolated audit-ssh MCP server."""

    target: str
    identity_file: Path
    known_hosts_policy: Literal["strict", "accept-new"] = "strict"

    def __post_init__(self) -> None:
        uri = self.target if self.target.startswith("ssh://") else f"ssh://{self.target}"
        SSHTarget.from_uri(uri)


def _require_stdio_params_cls() -> Any:
    try:
        mcp_mod = importlib.import_module("mcp")
        return mcp_mod.StdioServerParameters
    except ImportError as e:
        raise ImportError(
            "The 'mcp' package is required for MCP server parameter builders. "
            'Install via: uv pip install "host-audit-ai[crew]"'
        ) from e


def _require_mcp_adapter_cls() -> Any:
    try:
        ct_mod = importlib.import_module("crewai_tools")
        return ct_mod.MCPServerAdapter
    except ImportError as e:
        raise ImportError(
            "CrewAI MCP tools are required (crewai-tools[mcp]). "
            'Install via: uv pip install "host-audit-ai[crew]"'
        ) from e


def build_ssh_server_params(cfg: SSHServerConfig) -> Any:
    """Build StdioServerParameters for the read-only audit-ssh MCP server."""
    stdio_cls = _require_stdio_params_cls()
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", ""),
        "HOST_AUDIT_SSH_TARGET": cfg.target,
        "HOST_AUDIT_SSH_IDENTITY": str(cfg.identity_file.expanduser()),
        "HOST_AUDIT_SSH_HOST_KEY_POLICY": cfg.known_hosts_policy,
    }
    return stdio_cls(
        command=sys.executable,
        args=["-m", "host_audit_ai.mcp_servers.audit_ssh"],
        env=env,
    )


def build_web_server_params() -> list[Any]:
    """Build StdioServerParameters for air-gapped web search and web fetch MCP servers."""
    stdio_cls = _require_stdio_params_cls()
    return [
        stdio_cls(
            command="uvx",
            args=["--from", "duckduckgo-mcp-server[browser]", "duckduckgo-mcp-server"],
        ),
        stdio_cls(
            command="uvx",
            args=["mcp-server-fetch"],
        ),
    ]


@contextmanager
def ssh_mcp_adapter(cfg: SSHServerConfig) -> Iterator[Any]:
    """Context manager yielding ONLY read-only audit-ssh MCP tools."""
    adapter_cls = _require_mcp_adapter_cls()
    params = build_ssh_server_params(cfg)
    with adapter_cls(params) as tools:
        yield tools


@contextmanager
def web_mcp_adapter() -> Iterator[list[Any]]:
    """Context manager yielding ONLY air-gapped web search & fetch MCP tools."""
    adapter_cls = _require_mcp_adapter_cls()
    params_list = build_web_server_params()
    with ExitStack() as stack:
        combined_tools: list[Any] = []
        for params in params_list:
            tools = stack.enter_context(adapter_cls(params))
            combined_tools.extend(tools)
        yield combined_tools
