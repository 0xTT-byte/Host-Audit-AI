from pathlib import Path
import yaml
import pytest
from host_audit.rules.containers import check_containers

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent.parent / "baselines" / "docker-host.yml"


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


def test_containers_vulnerable_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "vulnerable_host"
    findings = check_containers(collect_dir, baseline)
    rule_ids = {f.rule_id for f in findings}

    # Should flag --privileged (CNT-001), docker.sock mount (CNT-002), sensitive host mount /etc (CNT-003),
    # host network mode (CNT-004), dangerous caps (CNT-005), and root user (CNT-006)
    assert "CNT-001" in rule_ids
    assert "CNT-002" in rule_ids
    assert "CNT-003" in rule_ids
    assert "CNT-004" in rule_ids
    assert "CNT-005" in rule_ids
    assert "CNT-006" in rule_ids
    assert len(findings) >= 6


def test_containers_clean_host(baseline: dict):
    collect_dir = FIXTURES_DIR / "clean_host"
    findings = check_containers(collect_dir, baseline)
    assert len(findings) == 0, f"Expected 0 findings on clean host, got: {[f.rule_id for f in findings]}"
