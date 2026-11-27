import json
from host_audit.schema import Finding, AttackChain, TriageReport


def test_finding_scoring_and_id():
    f = Finding(
        rule_id="EXP-002",
        domain="exposure",
        title="Critical service exposed",
        target="port:5432/tcp:postgres",
        evidence="0.0.0.0:5432",
        why_it_matters="Accessible without auth",
        verify_cmd="ss -tulpnH",
        remediation_hint="Bind to 127.0.0.1",
        reachability=3,
        privilege_gain=3,
        ease=3,
    )

    # 3 * 3 * 3 = 27 -> critical
    assert f.priority_score == 27
    assert f.severity == "critical"
    assert len(f.finding_id) == 64  # Full SHA-256 hex string

    f_low = Finding(
        rule_id="CNT-006",
        domain="containers",
        title="Container runs as root",
        target="container:app:user",
        evidence='"User": "root"',
        why_it_matters="Root in container",
        verify_cmd="docker inspect app",
        remediation_hint="Add non-root user",
        reachability=2,
        privilege_gain=1,
        ease=2,
    )
    # 2 * 1 * 2 = 4 -> low
    assert f_low.priority_score == 4
    assert f_low.severity == "low"


def test_triage_report_json_schema():
    schema = TriageReport.model_json_schema()
    assert "properties" in schema
    assert "executive_summary" in schema["properties"]
    assert "attack_chains" in schema["properties"]
    assert "false_positive_checks" in schema["properties"]

    report = TriageReport(
        executive_summary="Host has public database exposure and container breakout paths.",
        attack_chains=[
            AttackChain(
                name="Postgres RCE to Host Root",
                severity="critical",
                involved_rule_ids=["EXP-002", "CNT-001"],
                steps=["Access exposed port 5432", "Exploit privileged container", "Escape to host"],
                verify_cmds=["nc -zv host 5432"],
                fix_commands=["iptables -A DOCKER-USER -j DROP"],
            )
        ],
        false_positive_checks=["Verify if port 5432 is restricted at VPC edge"],
    )

    dumped = report.model_dump_json()
    reloaded = TriageReport.model_validate_json(dumped)
    assert len(reloaded.attack_chains) == 1
    assert reloaded.attack_chains[0].severity == "critical"
