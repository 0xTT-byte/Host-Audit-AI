"""Pure parser for installed package lists across multiple distros."""

from __future__ import annotations

import re

from host_audit_ai.models.snapshot import PackageInfo, ParseWarning


def parse_packages(raw_text: str, warnings: list[ParseWarning]) -> list[PackageInfo]:
    """Parse dpkg, rpm, pacman, or apk package listings into PackageInfo list."""
    packages: list[PackageInfo] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 1. dpkg / rpm tab-separated format: name\tversion\tarchitecture
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 2:
                name = parts[0].strip()
                version = parts[1].strip()
                arch = parts[2].strip() if len(parts) > 2 else ""
                packages.append(
                    PackageInfo(
                        name=name,
                        version=version,
                        architecture=arch,
                        source="package_manager",
                    )
                )
                continue

        # 2. pacman format: name version
        parts = line.split()
        if len(parts) == 2 and not line.endswith(":"):
            packages.append(
                PackageInfo(name=parts[0], version=parts[1], architecture="", source="pacman")
            )
            continue

        # 3. apk format e.g. musl-1.2.5-r0 ...
        if len(parts) >= 2 and re.match(r"^[A-Za-z0-9_\-\.]+-[0-9]", parts[0]):
            pkg_str = parts[0]
            # split on last two dashes e.g. name-1.2.3-r0
            match = re.match(r"^(.*?)-([0-9].*)$", pkg_str)
            if match:
                packages.append(
                    PackageInfo(
                        name=match.group(1),
                        version=match.group(2),
                        architecture="",
                        source="apk",
                    )
                )

    return packages
