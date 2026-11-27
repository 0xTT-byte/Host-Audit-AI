"""Pure parser for users, groups, and sudoers sections."""

from __future__ import annotations

import re

from host_audit_ai.models.snapshot import ParseWarning, SudoRule, UserAccount

LOCKED_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/sync",
}


def parse_users_passwd(raw_text: str, warnings: list[ParseWarning]) -> list[UserAccount]:
    """Parse /etc/passwd text into a list of UserAccount objects."""
    users: list[UserAccount] = []
    for line_num, line in enumerate(raw_text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 7:
            warnings.append(
                ParseWarning(
                    section_name="users_passwd",
                    message=(
                        f"Malformed passwd entry on line {line_num} "
                        f"(expected 7 fields, got {len(parts)})"
                    ),
                    raw_line=line,
                )
            )
            continue

        username = parts[0]
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            warnings.append(
                ParseWarning(
                    section_name="users_passwd",
                    message=f"Non-integer UID/GID on line {line_num}",
                    raw_line=line,
                )
            )
            continue

        home = parts[5]
        shell = parts[6]
        is_root_equivalent = uid == 0
        locked = shell in LOCKED_SHELLS or parts[1] in ("!", "*", "x!")

        users.append(
            UserAccount(
                username=username,
                uid=uid,
                gid=gid,
                home=home,
                shell=shell,
                is_root_equivalent=is_root_equivalent,
                locked=locked,
            )
        )

    return users


def parse_sudoers(raw_text: str, warnings: list[ParseWarning]) -> list[SudoRule]:
    """Parse sudoers and sudo -l output into normalized SudoRule entries."""
    rules: list[SudoRule] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("Defaults"):
            continue

        # Look for sudo rules e.g.:
        # root ALL=(ALL:ALL) ALL
        # user ALL=(ALL) NOPASSWD: ALL
        # %wheel ALL=(ALL) NOPASSWD: /usr/bin/vim, /bin/sh
        # (root) NOPASSWD: ALL (from sudo -l)
        nopasswd = "NOPASSWD:" in line

        # Match pattern: <target> <hosts>=(<run_as>) [NOPASSWD:] <commands>
        match = re.match(
            r"^(%?[A-Za-z0-9_\-\.]+)\s+([A-Za-z0-9_\-\*]+)\s*=\s*\((.*?)\)\s*(?:NOPASSWD:\s*)?(.*)$",
            line,
        )
        if match:
            user_or_group = match.group(1)
            hosts = match.group(2)
            run_as = match.group(3)
            cmds_raw = match.group(4)
            commands = [c.strip() for c in cmds_raw.split(",") if c.strip()]
            rules.append(
                SudoRule(
                    user_or_group=user_or_group,
                    hosts=hosts,
                    run_as=run_as,
                    commands=commands,
                    nopasswd=nopasswd,
                )
            )
        elif line.startswith("(") and "NOPASSWD:" in line:
            # sudo -l output format e.g. "(ALL) NOPASSWD: ALL"
            cmd_part = line.split("NOPASSWD:", 1)[1].strip()
            commands = [c.strip() for c in cmd_part.split(",") if c.strip()]
            rules.append(
                SudoRule(
                    user_or_group="current_user",
                    hosts="ALL",
                    run_as="ALL",
                    commands=commands,
                    nopasswd=True,
                )
            )

    return rules
