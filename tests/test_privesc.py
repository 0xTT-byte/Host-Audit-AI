from pathlib import Path
import yaml
import pytest
from host_audit.rules.privesc import check_privesc

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent.parent / "baselines" / "docker-host.yml"


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


def test_privesc_vulnerable_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "vulnerable_host"
    findings = check_privesc(collect_dir, baseline)
    rule_ids = {f.rule_id for f in findings}

    # Should flag NOPASSWD in sudoers (PRV-001), GTFOBins binary 'find' in sudoers (PRV-002),
    # SUID GTFOBins binary python3 (PRV-003), and dangerous capability cap_dac_override (PRV-004)
    assert "PRV-001" in rule_ids
    assert "PRV-002" in rule_ids
    assert "PRV-003" in rule_ids
    assert "PRV-004" in rule_ids
    assert len(findings) >= 4


def test_privesc_clean_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "clean_host"
    findings = check_privesc(collect_dir, baseline)
    assert len(findings) == 0, f"Expected 0 findings on clean host, got: {[f.rule_id for f in findings]}"
