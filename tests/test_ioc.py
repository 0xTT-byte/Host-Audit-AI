from pathlib import Path
import yaml
import pytest
from host_audit.rules.ioc import check_ioc

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent.parent / "baselines" / "docker-host.yml"


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


def test_ioc_vulnerable_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "vulnerable_host"
    findings = check_ioc(collect_dir, baseline)
    rule_ids = {f.rule_id for f in findings}

    # Should flag deleted running binary (IOC-001) and execution from /tmp (IOC-002)
    assert "IOC-001" in rule_ids
    assert "IOC-002" in rule_ids
    assert len(findings) >= 2


def test_ioc_clean_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "clean_host"
    findings = check_ioc(collect_dir, baseline)
    assert len(findings) == 0, f"Expected 0 findings on clean host, got: {[f.rule_id for f in findings]}"
