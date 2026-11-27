"""Pure parser for file permissions, SUID binaries, and file capabilities."""

from __future__ import annotations

import re

from host_audit_ai.models.snapshot import FilePermCheck, ParseWarning, SuidBinary

# Standard known binaries that commonly provide shell escapes when granted SUID
GTFOBINS = {
    "apt",
    "apt-get",
    "ash",
    "awk",
    "base64",
    "bash",
    "busybox",
    "cat",
    "chmod",
    "chown",
    "cp",
    "csh",
    "curl",
    "cut",
    "dash",
    "date",
    "dd",
    "diff",
    "dmesg",
    "dmsetup",
    "docker",
    "dpkg",
    "ed",
    "emacs",
    "env",
    "find",
    "flock",
    "fmt",
    "ftp",
    "gawk",
    "gdb",
    "git",
    "grep",
    "head",
    "ionice",
    "jq",
    "ksh",
    "ld.so",
    "less",
    "ltrace",
    "lua",
    "make",
    "man",
    "more",
    "mv",
    "nano",
    "nc",
    "netcat",
    "nice",
    "nmap",
    "node",
    "nohup",
    "openssl",
    "perl",
    "php",
    "pkexec",
    "python",
    "python3",
    "python3.10",
    "python3.11",
    "python3.12",
    "python3.13",
    "ruby",
    "rvim",
    "sed",
    "setfacl",
    "sh",
    "socat",
    "sort",
    "split",
    "strace",
    "systemctl",
    "tail",
    "tar",
    "taskset",
    "tee",
    "tftp",
    "time",
    "timeout",
    "ul",
    "unshare",
    "vi",
    "vim",
    "watch",
    "wget",
    "whois",
    "xargs",
    "xxd",
    "zip",
    "zsh",
}


def parse_file_perms(raw_text: str, warnings: list[ParseWarning]) -> list[FilePermCheck]:
    """Parse stat output lines into FilePermCheck entries."""
    checks: list[FilePermCheck] = []

    for line_num, line in enumerate(raw_text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("===") or line.startswith("#"):
            continue
        # Ignore ls -ld fallback lines (begin with file type & rwx permissions)
        if re.match(r"^[-dlcbps][-rwxsStT]{9}", line):
            continue

        # Format: '%a %u:%g %U:%G %F %n' or '%a %u:%g %n'
        pattern = r"^([0-7]+)\s+([^\s]+)\s+(?:([^/\s]+:[^/\s]+)\s+)?(?:[^/]*\s)?(/.*)$"
        match = re.match(pattern, line)
        if match:
            mode = match.group(1)
            uid_gid = match.group(2)
            user_group = match.group(3) or uid_gid
            owner = user_group.split(":", 1)[0]
            group = user_group.split(":", 1)[1] if ":" in user_group else ""
            path = match.group(4).strip()

            # Check world writable (mode ends with 2, 3, 6, 7 in octal)
            last_digit = int(mode[-1])
            is_world_writable = bool(last_digit & 2)

            checks.append(
                FilePermCheck(
                    path=path,
                    permissions=mode,
                    owner=owner,
                    group=group,
                    is_world_writable=is_world_writable,
                )
            )
        else:
            warnings.append(
                ParseWarning(
                    section_name="critical_perms",
                    message=f"Unparseable file permission line on line {line_num}",
                    raw_line=line,
                )
            )

    return checks


def parse_suid_and_caps(
    raw_text: str, warnings: list[ParseWarning]
) -> tuple[list[SuidBinary], list[str]]:
    """Parse SUID/SGID listings and file capabilities."""
    suid_binaries: list[SuidBinary] = []
    capabilities: list[str] = []

    in_caps_section = False
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line == "=== CAPABILITIES ===":
            in_caps_section = True
            continue

        if in_caps_section:
            # getcap format e.g. /usr/bin/ping cap_net_raw=ep or /usr/bin/ping = cap_net_raw+ep
            if " " in line and ("=" in line or "+e" in line):
                capabilities.append(line)
            continue

        # SUID stat format e.g. 4755 0:0 /usr/bin/sudo
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[0].isdigit():
            mode = parts[0]
            owner_group = parts[1]
            path = parts[2]
            owner = owner_group.split(":")[0] if ":" in owner_group else "root"
            binary_name = path.rsplit("/", 1)[-1]
            known_gtfo = binary_name in GTFOBINS

            suid_binaries.append(
                SuidBinary(
                    path=path,
                    owner=owner,
                    permissions=mode,
                    known_gtfobins=known_gtfo,
                )
            )
        elif line.startswith("/"):
            # Plain find output /usr/bin/sudo
            binary_name = line.rsplit("/", 1)[-1]
            suid_binaries.append(
                SuidBinary(
                    path=line,
                    owner="root",
                    permissions="4755",
                    known_gtfobins=binary_name in GTFOBINS,
                )
            )

    return suid_binaries, capabilities
