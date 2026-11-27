from pathlib import Path
import yaml
import pytest
from host_audit.rules.exposure import check_exposure

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent.parent / "baselines" / "docker-host.yml"


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


def test_exposure_vulnerable_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "vulnerable_host"
    findings = check_exposure(collect_dir, baseline)
    rule_ids = {f.rule_id for f in findings}

    # Should detect EXP-001 (unexpected port 9000), EXP-002 (critical service postgres 5432), and EXP-003 (docker firewall bypass)
    assert "EXP-001" in rule_ids
    assert "EXP-002" in rule_ids
    assert "EXP-003" in rule_ids
    assert len(findings) >= 3


def test_exposure_clean_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "clean_host"
    findings = check_exposure(collect_dir, baseline)
    assert len(findings) == 0, f"Expected 0 findings on clean host, got: {[f.rule_id for f in findings]}"
