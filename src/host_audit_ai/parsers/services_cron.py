"""Pure parser for systemd service units and cron jobs."""

from __future__ import annotations

from host_audit_ai.models.snapshot import CronEntry, ParseWarning, ServiceUnit


def parse_systemd_units(raw_text: str, warnings: list[ParseWarning]) -> list[ServiceUnit]:
    """Parse systemctl active units and unit files into ServiceUnit list."""
    units: dict[str, ServiceUnit] = {}

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("UNIT"):
            continue

        parts = line.split()
        if not parts:
            continue

        name = parts[0]
        if not (name.endswith(".service") or name.endswith(".timer")):
            continue

        # Active unit listing line: name load_state active_state sub_state ...
        if len(parts) >= 4 and parts[1] in ("loaded", "not-found", "error"):
            load_state = parts[1]
            active_state = parts[2]
            sub_state = parts[3]
            units[name] = ServiceUnit(
                name=name,
                load_state=load_state,
                active_state=active_state,
                sub_state=sub_state,
                enabled=units.get(name, ServiceUnit(name=name)).enabled,
            )
        elif len(parts) >= 2 and parts[1] in (
            "enabled",
            "disabled",
            "static",
            "masked",
            "indirect",
        ):
            # Unit file listing line: name status
            enabled = parts[1] == "enabled"
            if name in units:
                existing = units[name]
                units[name] = ServiceUnit(
                    name=name,
                    load_state=existing.load_state,
                    active_state=existing.active_state,
                    sub_state=existing.sub_state,
                    enabled=enabled,
                )
            else:
                units[name] = ServiceUnit(
                    name=name,
                    load_state="",
                    active_state="",
                    sub_state="",
                    enabled=enabled,
                )

    return list(units.values())


def parse_cron(raw_text: str, warnings: list[ParseWarning]) -> list[CronEntry]:
    """Parse crontab and cron spool text into CronEntry list."""
    entries: list[CronEntry] = []
    current_source = "/etc/crontab"

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("### FILE:") or line.startswith("### SPOOL:"):
            current_source = line.split(":", 1)[1].strip()
            continue

        if line.startswith("#") or line.startswith("===") or "=" in line.split()[0]:
            # Comments or environment settings (e.g. SHELL=/bin/sh)
            continue

        parts = line.split()
        # System crontab format: min hour dom mon dow user cmd... (>= 7 fields)
        # User crontab format:   min hour dom mon dow cmd...      (>= 6 fields)
        if len(parts) >= 7:
            schedule = " ".join(parts[:5])
            user = parts[5]
            cmd = " ".join(parts[6:])
            entries.append(
                CronEntry(
                    schedule=schedule,
                    user=user,
                    command=cmd,
                    source_file=current_source,
                )
            )
        elif len(parts) >= 6:
            schedule = " ".join(parts[:5])
            user = "current_user"
            cmd = " ".join(parts[5:])
            entries.append(
                CronEntry(
                    schedule=schedule,
                    user=user,
                    command=cmd,
                    source_file=current_source,
                )
            )

    return entries
