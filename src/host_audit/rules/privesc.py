import os
import re
from pathlib import Path
from typing import Any
from host_audit.schema import Finding

# Standard known binaries that commonly provide shell escapes when granted SUID or unrestricted sudo
GTFOBINS = {
    "apt", "apt-get", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown",
    "cp", "csh", "curl", "cut", "dash", "date", "dd", "diff", "dmesg", "dmsetup", "docker",
    "dpkg", "ed", "emacs", "env", "find", "flock", "fmt", "ftp", "gawk", "gdb", "git",
    "grep", "head", "ionice", "jq", "ksh", "ld.so", "less", "ltrace", "lua", "make",
    "man", "more", "mv", "nano", "nc", "netcat", "nice", "nmap", "node", "nohup", "openssl",
    "perl", "php", "pkexec", "python", "python3", "python3.10", "python3.11", "python3.12",
    "python3.13", "ruby", "rvim", "sed", "setfacl", "sh", "socat", "sort", "split", "strace",
    "systemctl", "tail", "tar", "taskset", "tee", "tftp", "time", "timeout", "ul", "unshare",
    "vi", "vim", "watch", "wget", "whois", "xargs", "xxd", "zip", "zsh"
}

# Standard system SUID utilities that are expected by default
EXPECTED_SYSTEM_SUID = {
    "sudo", "su", "passwd", "mount", "umount", "chfn", "chsh", "gpasswd",
    "newgrp", "ping", "ping6", "pkexec", "ssh-keysign", "sudoedit"
}

DANGEROUS_CAPS = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_chroot"
}


def check_privesc(collect_dir: Path, baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Sudoers checks (sudoers.txt)
    sudoers_file = collect_dir / "sudoers.txt"
    if sudoers_file.exists():
        lines = sudoers_file.read_text(errors="replace").splitlines()
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue

            # Flag NOPASSWD entries
            if "NOPASSWD" in line:
                findings.append(
                    Finding(
                        rule_id="PRV-001",
                        domain="privesc",
                        title=f"Sudoers rule grants passwordless execution: {line[:60]}",
                        target=f"sudoers:{line[:40]}",
                        evidence=line,
                        why_it_matters="NOPASSWD entries allow local users or compromised service accounts to execute privileged commands without entering credentials.",
                        verify_cmd="sudo -l",
                        remediation_hint="Require password authentication for sudo actions or restrict commands to minimal specific scripts.",
                        reachability=1,
                        privilege_gain=3,
                        ease=3,
                    )
                )

            # Flag wildcard or broad execution commands or GTFOBins binaries
            lower_line = line.lower()
            for binary in GTFOBINS:
                # Match standalone binary in sudoers rule path, e.g. /usr/bin/vim or /usr/bin/find
                pattern = rf'(?:/|\s){re.escape(binary)}(?:\s|$)'
                if re.search(pattern, lower_line) and "nopasswd" in lower_line:
                    findings.append(
                        Finding(
                            rule_id="PRV-002",
                            domain="privesc",
                            title=f"Sudoers grants access to shell-escape capable binary '{binary}'",
                            target=f"sudoers:bin:{binary}",
                            evidence=line,
                            why_it_matters=f"Binary '{binary}' is documented in GTFOBins and can be trivially abused to break out into an interactive root shell.",
                            verify_cmd=f"sudo -l | grep -i '{binary}'",
                            remediation_hint=f"Avoid granting sudo access to '{binary}'; wrap necessary commands in restricted wrapper scripts.",
                            reachability=1,
                            privilege_gain=3,
                            ease=3,
                        )
                    )
                    break

    # 2. SUID checks (suid.txt)
    suid_file = collect_dir / "suid.txt"
    if suid_file.exists():
        for line in suid_file.read_text(errors="replace").splitlines():
            path = line.strip()
            if not path or path.startswith("###"):
                continue

            basename = os.path.basename(path).lower()
            # If the binary is in GTFOBins and NOT a standard expected SUID binary
            if basename in GTFOBINS and basename not in EXPECTED_SYSTEM_SUID:
                findings.append(
                    Finding(
                        rule_id="PRV-003",
                        domain="privesc",
                        title=f"High-risk SUID binary with known privilege escalation vector: {path}",
                        target=f"suid:{path}",
                        evidence=path,
                        why_it_matters=f"The SUID bit on '{path}' allows any unprivileged user to execute it with elevated permissions and spawn a root shell.",
                        verify_cmd=f"ls -l {path}",
                        remediation_hint=f"Remove the SUID bit: 'chmod u-s {path}'.",
                        reachability=1,
                        privilege_gain=3,
                        ease=3,
                    )
                )

    # 3. Capabilities checks (caps.txt)
    caps_file = collect_dir / "caps.txt"
    if caps_file.exists():
        for line in caps_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("###"):
                continue

            parts = line.split(None, 1)
            file_part = parts[0]
            caps_part = parts[1].lower() if len(parts) > 1 else ""

            for cap in DANGEROUS_CAPS:
                if cap in caps_part or cap in line.lower():
                    findings.append(
                        Finding(
                            rule_id="PRV-004",
                            domain="privesc",
                            title=f"Dangerous capability '{cap}' assigned to binary {file_part}",
                            target=f"cap:{file_part}:{cap}",
                            evidence=line,
                            why_it_matters=f"Capability '{cap}' gives the executable kernel-level privileges (e.g. arbitrary UID change or full filesystem read/write bypass).",
                            verify_cmd=f"getcap {file_part}",
                            remediation_hint=f"Remove file capabilities: 'setcap -r {file_part}'.",
                            reachability=1,
                            privilege_gain=3,
                            ease=3,
                        )
                    )

    return findings
