from pathlib import Path
from host_audit.schema import Finding
from host_audit.store import AuditStore


def test_audit_store_state_tracking(tmp_path: Path):
    db_file = tmp_path / "test_history.db"

    f1 = Finding(
        rule_id="SSH-001",
        domain="ssh",
        title="PermitRootLogin is yes",
        target="sshd:permitrootlogin",
        evidence="permitrootlogin yes",
        why_it_matters="Direct root login allowed",
        verify_cmd="sshd -T",
        remediation_hint="Set PermitRootLogin no",
        reachability=3,
        privilege_gain=3,
        ease=2,
    )

    f2 = Finding(
        rule_id="EXP-001",
        domain="exposure",
        title="Unexpected public listener 9000/tcp",
        target="port:9000/tcp",
        evidence="0.0.0.0:9000",
        why_it_matters="Service exposed",
        verify_cmd="ss -tulpnH",
        remediation_hint="Bind to 127.0.0.1",
        reachability=3,
        privilege_gain=2,
        ease=2,
    )

    with AuditStore(db_file) as store:
        # Run 1: Both findings are new
        diff1 = store.record_run("host1", [f1, f2])
        assert len(diff1["new"]) == 2
        assert len(diff1["persisting"]) == 0
        assert len(diff1["resolved_ids"]) == 0

        # Run 2: Same findings persist
        diff2 = store.record_run("host1", [f1, f2])
        assert len(diff2["new"]) == 0
        assert len(diff2["persisting"]) == 2
        assert len(diff2["resolved_ids"]) == 0

        # Run 3: f2 is resolved, only f1 persists
        diff3 = store.record_run("host1", [f1])
        assert len(diff3["new"]) == 0
        assert len(diff3["persisting"]) == 1
        assert len(diff3["resolved_ids"]) == 1
        assert diff3["resolved_ids"][0] == f2.finding_id
