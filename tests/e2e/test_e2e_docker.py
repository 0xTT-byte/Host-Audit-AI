"""Docker-backed live SSH end-to-end tests against a disposable vulnerable target."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from host_audit_ai.cli import app
from host_audit_ai.collectors.provisioning import (
    build_authorized_keys_entry,
    generate_audit_keypair,
)
from host_audit_ai.collectors.transport import SSHTarget
from host_audit_ai.mcp_servers.audit_ssh_core import AuditSSHClient
from host_audit_ai.models.report import AuditReport, RunDiff

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_PATH = REPO_ROOT / "tests" / "e2e" / "Dockerfile.vuln"
IMAGE_TAG = "host-audit-ai-e2e-vuln:test"


@dataclass(frozen=True)
class RunningVulnTarget:
    """Running vulnerable container metadata for E2E verification."""

    container_id: str
    ssh_port: int
    audituser_key: Path
    auditmcp_key: Path
    home_dir: Path


def _docker_bin() -> str | None:
    return shutil.which("docker")


def _docker_available() -> bool:
    docker = _docker_bin()
    if docker is None:
        return False
    proc = subprocess.run(  # noqa: S603
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.returncode == 0


@pytest.fixture(scope="module")
def e2e_docker_image() -> str:
    """Build disposable vulnerable target image if Docker daemon is accessible."""
    docker = _docker_bin()
    if docker is None or not _docker_available():
        pytest.skip("Docker daemon is unavailable in this environment")

    build_proc = subprocess.run(  # noqa: S603
        [
            docker,
            "build",
            "-f",
            str(DOCKERFILE_PATH),
            "-t",
            IMAGE_TAG,
            str(REPO_ROOT),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if build_proc.returncode != 0:
        pytest.fail(f"Failed to build E2E Dockerfile:\n{build_proc.stdout}\n{build_proc.stderr}")
    return IMAGE_TAG


@pytest.fixture
def vuln_container(
    e2e_docker_image: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RunningVulnTarget]:
    """Start ephemeral vulnerable Ubuntu container with collection and MCP keys."""
    docker = _docker_bin()
    assert docker is not None

    home_dir = tmp_path / "home"
    (home_dir / ".ssh").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("HOME", str(home_dir))

    keys_mount = tmp_path / "audit_keys"
    keys_mount.mkdir(parents=True, mode=0o755)

    audituser_pair = generate_audit_keypair(tmp_path / "audituser_ed25519")
    auditmcp_pair = generate_audit_keypair(tmp_path / "auditmcp_ed25519")

    (keys_mount / "audituser.pub").write_text(
        audituser_pair.public_key + "\n",
        encoding="utf-8",
    )
    forced_entry = build_authorized_keys_entry(auditmcp_pair.public_key)
    (keys_mount / "auditmcp_authorized_keys").write_text(
        forced_entry + "\n",
        encoding="utf-8",
    )

    run_proc = subprocess.run(  # noqa: S603
        [
            docker,
            "run",
            "-d",
            "-p",
            "127.0.0.1:0:22",
            "-v",
            f"{keys_mount}:/etc/audit-keys:ro",
            e2e_docker_image,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if run_proc.returncode != 0:
        pytest.fail(f"Failed to start E2E container: {run_proc.stderr}")

    container_id = run_proc.stdout.strip()
    try:
        port_proc = subprocess.run(  # noqa: S603
            [docker, "port", container_id, "22/tcp"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        mapped = port_proc.stdout.strip().splitlines()[0]
        ssh_port = int(mapped.rsplit(":", 1)[-1])

        # Wait until sshd accepts the forced-command ping check
        mcp_client = AuditSSHClient(
            target=SSHTarget(hostname="127.0.0.1", port=ssh_port, username="auditmcp"),
            identity_file=auditmcp_pair.private_key_path,
            known_hosts_policy="accept-new",
            timeout_seconds=10,
        )
        deadline = time.monotonic() + 30.0
        ready = False
        while time.monotonic() < deadline:
            res = mcp_client.ping()
            if res.ok and "host-audit-wrapper:ok" in res.stdout:
                ready = True
                break
            time.sleep(0.5)

        if not ready:
            logs_proc = subprocess.run(  # noqa: S603
                [docker, "logs", container_id],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            pytest.fail(
                f"Container SSH daemon did not become ready on port {ssh_port}:\n"
                f"{logs_proc.stdout}\n{logs_proc.stderr}"
            )

        yield RunningVulnTarget(
            container_id=container_id,
            ssh_port=ssh_port,
            audituser_key=audituser_pair.private_key_path,
            auditmcp_key=auditmcp_pair.private_key_path,
            home_dir=home_dir,
        )
    finally:
        subprocess.run(  # noqa: S603
            [docker, "rm", "-f", container_id],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )


@pytest.mark.e2e
def test_e2e_live_ssh_audit_drift_wrapper_and_sanitizer(
    vuln_container: RunningVulnTarget,
    tmp_path: Path,
) -> None:
    """Verify live SSH scan, drift diff, forced-command wrapper, SARIF, and sanitizer."""
    docker = _docker_bin()
    assert docker is not None

    runner = CliRunner()
    db_path = tmp_path / "e2e_audit.db"
    report1_path = tmp_path / "report1.json"
    report2_path = tmp_path / "report2.json"
    sarif_path = tmp_path / "results.sarif"
    target_uri = f"ssh://audituser@127.0.0.1:{vuln_container.ssh_port}"
    env_vars = {"HOME": str(vuln_container.home_dir), "PATH": os.environ.get("PATH", "")}

    # 1. Live SSH deterministic scan via ephemeral collect.sh
    scan1 = runner.invoke(
        app,
        [
            "scan",
            "--target",
            target_uri,
            "--identity",
            str(vuln_container.audituser_key),
            "--accept-new-host-key",
            "--db",
            str(db_path),
            "--format",
            "json",
            "--out",
            str(report1_path),
        ],
        env=env_vars,
    )
    assert scan1.exit_code == 2, (
        f"Expected exit 2 on vulnerable host, got {scan1.exit_code}:\n{scan1.output}"
    )

    report1 = AuditReport.model_validate_json(report1_path.read_text(encoding="utf-8"))
    fired_rules = {f.rule_id for f in report1.findings}
    expected_rules = {"SSH-001", "SSH-002", "SSH-003", "PRV-001", "FS-001", "CRN-001", "IOC-003"}
    missing = expected_rules - fired_rules
    assert not missing, f"Expected rules missing: {missing} (fired: {sorted(fired_rules)})"
    assert len(report1.exposure_chains) >= 2, "Expected multiple ExposureChains"

    # Assert zero temporary artifacts left by collect.sh inside target /tmp or /home/audituser
    tmp_ls = subprocess.run(  # noqa: S603
        [docker, "exec", vuln_container.container_id, "ls", "-A", "/tmp"],  # noqa: S108
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    tmp_entries = set(tmp_ls.stdout.split())
    assert tmp_entries == {"evil_cron.sh", "staged_miner.elf"}

    home_ls = subprocess.run(  # noqa: S603
        [docker, "exec", vuln_container.container_id, "ls", "-A", "/home/audituser"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert "collect" not in home_ls.stdout
    assert "audit" not in home_ls.stdout

    # 2. Mutate /etc/shadow permissions and verify RESOLVED drift detection
    subprocess.run(  # noqa: S603
        [docker, "exec", vuln_container.container_id, "chmod", "640", "/etc/shadow"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    scan2 = runner.invoke(
        app,
        [
            "scan",
            "--target",
            target_uri,
            "--identity",
            str(vuln_container.audituser_key),
            "--accept-new-host-key",
            "--db",
            str(db_path),
            "--format",
            "json",
            "--out",
            str(report2_path),
        ],
        env=env_vars,
    )
    assert scan2.exit_code == 2
    report2 = AuditReport.model_validate_json(report2_path.read_text(encoding="utf-8"))

    diff_res = runner.invoke(
        app,
        [
            "diff",
            "--base",
            report1.run_id,
            "--target",
            report2.run_id,
            "--db",
            str(db_path),
            "--json",
        ],
    )
    assert diff_res.exit_code == 0, diff_res.output
    run_diff = RunDiff.model_validate_json(diff_res.stdout)
    resolved_rules = {f.rule_id for f in run_diff.resolved}
    assert "FS-001" in resolved_rules, f"Expected FS-001 RESOLVED, got {resolved_rules}"

    # 3. Live AuditSSHClient forced-command wrapper verification against auditmcp
    mcp_client = AuditSSHClient(
        target=SSHTarget(hostname="127.0.0.1", port=vuln_container.ssh_port, username="auditmcp"),
        identity_file=vuln_container.auditmcp_key,
        known_hosts_policy="strict",
        timeout_seconds=15,
    )
    ping_res = mcp_client.ping()
    assert ping_res.ok
    assert ping_res.stdout.strip() == "host-audit-wrapper:ok"

    cfg_res = mcp_client.read_config_snippet("/etc/ssh/sshd_config", 1, 40)
    assert cfg_res.ok
    assert "PermitRootLogin yes" in cfg_res.stdout

    # Verify raw arbitrary commands are denied by server-side forced-command wrapper (exit 126)
    ssh_bin = shutil.which("ssh") or "/usr/bin/ssh"
    for blocked_cmd in ("cat /etc/shadow", "id"):
        raw_attempt = subprocess.run(  # noqa: S603
            [
                ssh_bin,
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-i",
                str(vuln_container.auditmcp_key),
                "-p",
                str(vuln_container.ssh_port),
                "--",
                "auditmcp@127.0.0.1",
                blocked_cmd,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert raw_attempt.returncode == 126, (
            f"Expected forced-command rejection (126) for '{blocked_cmd}', "
            f"got {raw_attempt.returncode}: {raw_attempt.stderr}"
        )
        assert "rejected" in raw_attempt.stderr.lower()

    # 4. SARIF 2.1.0 export verification
    export_res = runner.invoke(
        app,
        [
            "export",
            report1.run_id,
            "--format",
            "sarif",
            "--db",
            str(db_path),
            "--out",
            str(sarif_path),
        ],
    )
    assert export_res.exit_code == 0, export_res.output
    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) >= len(expected_rules)

    # 5. Deterministic sanitizer dry-run verification against live captured run
    triage_dry = runner.invoke(
        app,
        [
            "triage",
            report1.run_id,
            "--dry-run-sanitizer",
            "--db",
            str(db_path),
        ],
    )
    assert triage_dry.exit_code == 0, triage_dry.output
    sanitized_payload = json.loads(triage_dry.stdout)
    assert isinstance(sanitized_payload, list)
    assert sanitized_payload, "Expected non-empty sanitized Stage 2 queries"
    serialized = triage_dry.stdout.lower()
    for sensitive in ("audituser", "devuser", "auditmcp", report1.hostname.lower()):
        if sensitive not in ("localhost", "unknown"):
            assert sensitive not in serialized, f"Leaked '{sensitive}' in sanitizer output"
