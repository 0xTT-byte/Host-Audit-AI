from host_audit.schema import Finding, TriageReport, AttackChain
from host_audit.report import generate_markdown_report


def test_generate_markdown_report_no_llm():
    f = Finding(
        rule_id="SSH-001",
        domain="ssh",
        title="Root SSH login permitted",
        target="sshd:permitrootlogin",
        evidence="permitrootlogin yes",
        why_it_matters="Brute force risk",
        verify_cmd="sshd -T",
        remediation_hint="Set PermitRootLogin no",
        reachability=3,
        privilege_gain=3,
        ease=2,
    )
    diff = {"new": [f], "persisting": [], "resolved_ids": []}

    md = generate_markdown_report("test-host", [f], diff, triage=None)
    assert "# Host Security Audit Report: `test-host`" in md
    assert "AI correlation was disabled or skipped (`--no-llm`)" in md
    assert "SSH-001" in md
    assert "permitrootlogin yes" in md


def test_generate_markdown_report_with_triage():
    f = Finding(
        rule_id="EXP-002",
        domain="exposure",
        title="Critical service exposed",
        target="port:5432/tcp:postgres",
        evidence="0.0.0.0:5432",
        why_it_matters="DB exposure",
        verify_cmd="ss -tulpnH",
        remediation_hint="Bind to 127.0.0.1",
        reachability=3,
        privilege_gain=3,
        ease=3,
    )
    diff = {"new": [f], "persisting": [], "resolved_ids": []}

    triage = TriageReport(
        executive_summary="Critical database exposure detected.",
        attack_chains=[
            AttackChain(
                name="Database Compromise",
                severity="critical",
                involved_rule_ids=["EXP-002"],
                steps=["Access DB", "Execute commands"],
                verify_cmds=["nc -zv host 5432"],
                fix_commands=["bind to localhost"],
            )
        ],
        false_positive_checks=["Check firewall rules"],
    )

    md = generate_markdown_report("test-host", [f], diff, triage=triage)
    assert "Critical database exposure detected." in md
    assert "## Correlated Attack Chains" in md
    assert "Database Compromise `[CRITICAL]`" in md
