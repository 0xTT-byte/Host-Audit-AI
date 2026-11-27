"""Test strict one-way architecture boundary invariants."""

from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_ROOTS = {
    "crewai",
    "crewai_tools",
    "mcp",
    "ollama",
    "litellm",
    "openai",
    "host_audit_ai.crew",
    "host_audit_ai.mcp_servers",
}


def _check_import(module_name: str, file_path: Path) -> list[str]:
    violations: list[str] = []
    for forbidden in FORBIDDEN_ROOTS:
        if module_name == forbidden or module_name.startswith(f"{forbidden}."):
            violations.append(f"{file_path}: forbidden import '{module_name}'")
    return violations


def test_architecture_boundary_ast() -> None:
    """Assert models, collectors, parsers, engine, storage, exporters, and cli never import AI."""
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src" / "host_audit_ai"

    scanned_dirs = [
        src_dir / "models",
        src_dir / "collectors",
        src_dir / "parsers",
        src_dir / "engine",
        src_dir / "storage",
        src_dir / "exporters",
    ]

    py_files: list[Path] = []
    for d in scanned_dirs:
        if d.exists():
            py_files.extend(d.rglob("*.py"))

    cli_file = src_dir / "cli.py"
    if cli_file.exists():
        py_files.append(cli_file)

    assert py_files, "Expected to find python source files to check"

    all_violations: list[str] = []
    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    all_violations.extend(_check_import(alias.name, file_path))
            elif isinstance(node, ast.ImportFrom) and node.module:
                all_violations.extend(_check_import(node.module, file_path))

    assert not all_violations, "Architecture boundary violations found:\n" + "\n".join(
        all_violations
    )


def test_core_imports_without_crew() -> None:
    """Assert core packages can be imported without crew dependencies."""
    import host_audit_ai.cli
    import host_audit_ai.collectors.provisioning
    import host_audit_ai.engine
    import host_audit_ai.models

    assert host_audit_ai.models is not None
    assert host_audit_ai.engine is not None
    assert host_audit_ai.cli is not None
    assert host_audit_ai.collectors.provisioning is not None
