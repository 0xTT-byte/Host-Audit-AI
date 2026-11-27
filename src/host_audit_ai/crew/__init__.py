"""Optional [crew] multi-agent triage and scoped tool adapters."""

from host_audit_ai.crew.mcp_tools import (
    SSHServerConfig,
    build_ssh_server_params,
    build_web_server_params,
    ssh_mcp_adapter,
    web_mcp_adapter,
)
from host_audit_ai.crew.skills_writer import (
    JailedSkillsWriter,
    SkillsWriterError,
    build_skills_writer_crewai_tool,
)

__all__ = [
    "JailedSkillsWriter",
    "SSHServerConfig",
    "SkillsWriterError",
    "build_skills_writer_crewai_tool",
    "build_ssh_server_params",
    "build_web_server_params",
    "ssh_mcp_adapter",
    "web_mcp_adapter",
]
