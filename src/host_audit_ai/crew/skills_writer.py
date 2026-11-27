"""Path-jailed remediation artifact writer strictly scoped to ./skills/."""

from __future__ import annotations

import hashlib
import importlib
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from host_audit_ai.models.triage import RemediationArtifact

_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")

_EXT_TO_LANG: dict[str, Literal["bash", "python", "ansible", "markdown"]] = {
    ".sh": "bash",
    ".py": "python",
    ".yml": "ansible",
    ".yaml": "ansible",
    ".md": "markdown",
}


class SkillsWriterError(Exception):
    """Raised when a jailed skills write violates security or size constraints."""


class JailedSkillsWriter:
    """Writes unapproved, non-executable remediation artifacts strictly inside base_dir."""

    def __init__(self, base_dir: Path = Path("./skills"), max_bytes: int = 65536) -> None:
        self.base_dir = base_dir
        self.max_bytes = max_bytes
        self.written_artifacts: list[RemediationArtifact] = []

    def _validate_filename(
        self, filename: str
    ) -> tuple[str, Literal["bash", "python", "ansible", "markdown"]]:
        if not filename or "\x00" in filename:
            raise SkillsWriterError("Invalid empty or null-byte filename")
        if "/" in filename or "\\" in filename or ".." in filename or filename.startswith("."):
            raise SkillsWriterError(f"Path traversal or directory separator rejected: '{filename}'")
        if not _FILENAME_RE.fullmatch(filename):
            raise SkillsWriterError(f"Filename '{filename}' does not match allowed pattern")

        ext = Path(filename).suffix.lower()
        if ext not in _EXT_TO_LANG:
            raise SkillsWriterError(
                f"Extension '{ext or '<none>'}' not allowed. "
                f"Allowed: {', '.join(sorted(_EXT_TO_LANG))}"
            )
        return filename, _EXT_TO_LANG[ext]

    def write(self, filename: str, content: str, summary: str) -> RemediationArtifact:
        """Validate, jail-check, write with 0o644 (O_NOFOLLOW), and return RemediationArtifact."""
        clean_name, lang = self._validate_filename(filename)

        encoded = content.encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise SkillsWriterError(
                f"Content size ({len(encoded)} bytes) exceeds max_bytes ({self.max_bytes})"
            )

        if self.base_dir.is_symlink():
            raise SkillsWriterError("Base skills directory must not be a symlink")

        self.base_dir.mkdir(parents=True, exist_ok=True)
        if self.base_dir.is_symlink():
            raise SkillsWriterError("Base skills directory must not be a symlink")

        resolved_base = self.base_dir.resolve()
        candidate = self.base_dir / clean_name
        if candidate.is_symlink():
            raise SkillsWriterError(f"Target file '{clean_name}' is a symlink (rejected)")

        resolved_target = candidate.resolve()
        if not resolved_target.is_relative_to(resolved_base):
            raise SkillsWriterError(f"Target '{clean_name}' escapes skills jail")
        if resolved_target.parent != resolved_base:
            raise SkillsWriterError(f"Subdirectory writes are disallowed: '{clean_name}'")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags, 0o644)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(encoded)
        except Exception:
            raise

        if os.name == "posix":
            os.chmod(candidate, 0o644)

        digest = hashlib.sha256(encoded).hexdigest()
        artifact = RemediationArtifact(
            filename=clean_name,
            language=lang,
            summary=summary.strip(),
            approved=False,
            sha256=digest,
        )
        self.written_artifacts = [
            existing for existing in self.written_artifacts if existing.filename != clean_name
        ]
        self.written_artifacts.append(artifact)
        return artifact


class _SkillsWriterInput(BaseModel):
    filename: str = Field(
        ...,
        description="Safe flat filename ending in .sh, .py, .yml, .yaml, or .md",
    )
    content: str = Field(..., description="Remediation script or documentation contents")
    summary: str = Field(..., description="Concise summary of what the artifact remediates")


def build_skills_writer_crewai_tool(writer: JailedSkillsWriter) -> Any:
    """Build a CrewAI BaseTool wrapping JailedSkillsWriter (requires [crew] extra)."""
    try:
        crewai_tools_mod = importlib.import_module("crewai.tools")
        base_tool_cls = crewai_tools_mod.BaseTool
    except ImportError as e:
        raise ImportError(
            "CrewAI optional dependencies are required for build_skills_writer_crewai_tool. "
            'Install via: uv pip install "host-audit-ai[crew]"'
        ) from e

    class JailedSkillsWriterTool(base_tool_cls):  # type: ignore[valid-type,misc]
        name: str = "write_remediation_skill"
        description: str = (
            "Write a non-executable remediation script or playbook safely inside ./skills/."
        )
        args_schema: type[BaseModel] = _SkillsWriterInput

        def _run(self, filename: str, content: str, summary: str) -> str:
            artifact = writer.write(filename=filename, content=content, summary=summary)
            return artifact.model_dump_json()

    return JailedSkillsWriterTool()
