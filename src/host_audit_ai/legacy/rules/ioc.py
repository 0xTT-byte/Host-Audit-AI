import re
from pathlib import Path
from typing import Any
from host_audit.schema import Finding

TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def check_ioc(collect_dir: Path, baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Deleted binary execution check (deleted-procs.txt)
    deleted_file = collect_dir / "deleted-procs.txt"
    if deleted_file.exists():
        for line in deleted_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("###"):
                continue

            # Format example:
            # lrwxrwxrwx 1 root root 0 Nov 23 12:00 /proc/1234/exe -> /tmp/miner (deleted)
            match = re.search(r'/proc/(\d+)/exe\s*->\s*(.+?)(?:\s+\(deleted\))?$', line)
            if match:
                pid = match.group(1)
                exe_target = match.group(2).strip()

                findings.append(
                    Finding(
                        rule_id="IOC-001",
                        domain="ioc",
                        title=f"Running process PID {pid} executes deleted binary on disk: {exe_target}",
                        target=f"proc:{pid}:{exe_target}",
                        evidence=line,
                        why_it_matters="Adversaries and stealth malware frequently delete binaries from disk immediately after launch to evade signature scanners and file-integrity checks.",
                        verify_cmd=f"ls -l /proc/{pid}/exe && pwdx {pid} 2>/dev/null",
                        remediation_hint=f"Investigate process PID {pid} via 'cat /proc/{pid}/cmdline', identify parent process, and terminate if unauthorized.",
                        reachability=2,
                        privilege_gain=2,
                        ease=2,
                    )
                )

                # Check if it was running from a temporary directory
                for temp_dir in TEMP_DIRS:
                    if temp_dir in exe_target:
                        findings.append(
                            Finding(
                                rule_id="IOC-002",
                                domain="ioc",
                                title=f"Process PID {pid} executing out of temporary path: {exe_target}",
                                target=f"proc:{pid}:tmpdir",
                                evidence=line,
                                why_it_matters="Execution from world-writable directories like /tmp or /dev/shm is a common tactic for dropped payloads and unauthorized tools.",
                                verify_cmd=f"ls -l /proc/{pid}/exe",
                                remediation_hint=f"Kill process PID {pid} and mount /tmp with 'noexec' if possible.",
                                reachability=2,
                                privilege_gain=3,
                                ease=2,
                            )
                        )
                        break

    return findings
