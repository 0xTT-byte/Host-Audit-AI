from pathlib import Path
import yaml
import pytest
from host_audit.rules.ssh import check_ssh_and_users

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent.parent / "baselines" / "docker-host.yml"


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


def test_ssh_and_users_vulnerable_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "vulnerable_host"
    findings = check_ssh_and_users(collect_dir, baseline)
    rule_ids = {f.rule_id for f in findings}

    # Should flag PermitRootLogin (SSH-001), PasswordAuthentication (SSH-002), MaxAuthTries (SSH-003),
    # Missing allow list (SSH-004), and rogue UID 0 account 'backdoor' (AUTH-001)
    assert "SSH-001" in rule_ids
    assert "SSH-002" in rule_ids
    assert "SSH-003" in rule_ids
    assert "SSH-004" in rule_ids
    assert "AUTH-001" in rule_ids
    assert len(findings) >= 5


def test_ssh_and_users_clean_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "clean_host"
    findings = check_ssh_and_users(collect_dir, baseline)
    assert len(findings) == 0, f"Expected 0 findings on clean host, got: {[f.rule_id for f in findings]}"
