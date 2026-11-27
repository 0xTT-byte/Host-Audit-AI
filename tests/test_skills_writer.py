"""Security tests for path-jailed ./skills/ artifact writer."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from host_audit_ai.crew.skills_writer import (
    JailedSkillsWriter,
    SkillsWriterError,
    build_skills_writer_crewai_tool,
)


def test_skills_writer_valid_artifacts_and_mode(tmp_path: Path) -> None:
    skills_dir = tmp_path / "skills"
    writer = JailedSkillsWriter(base_dir=skills_dir)

    cases = [
        ("fix_ssh.sh", "#!/bin/bash\necho fix\n", "bash"),
        ("check_sysctl.py", "print('ok')\n", "python"),
        ("harden.yml", "- hosts: all\n", "ansible"),
        ("notes.md", "# Remediation\n", "markdown"),
    ]

    for fname, content, expected_lang in cases:
        artifact = writer.write(fname, content, f"Remediation {fname}")
        target = skills_dir / fname
        assert target.is_file()
        assert artifact.filename == fname
        assert artifact.language == expected_lang
        assert artifact.approved is False
        assert artifact.sha256 == hashlib.sha256(content.encode("utf-8")).hexdigest()
        if os.name == "posix":
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode == 0o644
            assert (mode & 0o111) == 0


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "../escape.sh",
        "/tmp/abs.sh",  # noqa: S108
        "sub/dir.sh",
        "sub\\dir.sh",
        ".hidden.sh",
        "evil.exe",
        "noext",
        "bad\x00.sh",
        "space name.sh",
    ],
)
def test_skills_writer_rejects_traversal_and_bad_names(tmp_path: Path, bad_name: str) -> None:
    writer = JailedSkillsWriter(base_dir=tmp_path / "skills")
    with pytest.raises(SkillsWriterError):
        writer.write(bad_name, "echo hi\n", "bad")


def test_skills_writer_rejects_oversized_and_symlinks(tmp_path: Path) -> None:
    skills_dir = tmp_path / "skills"
    writer = JailedSkillsWriter(base_dir=skills_dir, max_bytes=32)

    with pytest.raises(SkillsWriterError, match="exceeds max_bytes"):
        writer.write("big.sh", "X" * 64, "too big")

    # Pre-planted symlink target inside skills_dir pointing outside
    skills_dir.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.sh"
    outside.write_text("original", encoding="utf-8")
    planted = skills_dir / "planted.sh"
    planted.symlink_to(outside)

    with pytest.raises(SkillsWriterError, match="symlink"):
        writer.write("planted.sh", "overwrite", "symlink attack")
    assert outside.read_text(encoding="utf-8") == "original"

    # Symlinked base_dir itself
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    symlink_base = tmp_path / "sym_skills"
    symlink_base.symlink_to(real_dir)
    sym_writer = JailedSkillsWriter(base_dir=symlink_base)
    with pytest.raises(SkillsWriterError, match="symlink"):
        sym_writer.write("ok.sh", "echo 1", "sym base")


def test_skills_writer_crewai_tool_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("CREWAI_STORAGE_DIR", "host-audit-ai-test")
    pytest.importorskip("crewai")
    writer = JailedSkillsWriter(base_dir=tmp_path / "skills")
    tool = build_skills_writer_crewai_tool(writer)
    raw_out = tool._run(
        filename="crew_fix.sh",
        content="echo remediate\n",
        summary="Fix via CrewAI tool",
    )
    assert "crew_fix.sh" in raw_out
    assert (tmp_path / "skills" / "crew_fix.sh").is_file()
