"""Pure parser for sshd_effective section into SshdConfig."""

from __future__ import annotations

from host_audit_ai.models.snapshot import ParseWarning, SshdConfig


def parse_sshd(raw_text: str, warnings: list[ParseWarning]) -> SshdConfig:
    """Parse sshd -T effective dump and raw sshd_config into SshdConfig.

    Effective sshd -T options take precedence over raw sshd_config lines.
    """
    raw_options: dict[str, str] = {}

    lines = raw_text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if " " not in line and "\t" not in line:
            continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            continue

        key = parts[0].lower()
        val = parts[1].strip()

        # First appearance in sshd -T wins; for raw files first declaration wins in sshd
        if key not in raw_options:
            raw_options[key] = val

    port = 22
    if "port" in raw_options:
        try:
            port = int(raw_options["port"].split()[0])
        except ValueError:
            warnings.append(
                ParseWarning(
                    section_name="sshd_effective",
                    message=f"Non-integer SSH port '{raw_options['port']}'",
                )
            )

    permit_root = raw_options.get("permitrootlogin", "unknown").lower()
    pass_auth_str = raw_options.get("passwordauthentication", "no").lower()
    pass_auth = pass_auth_str in ("yes", "true", "1")

    pubkey_auth_str = raw_options.get("pubkeyauthentication", "yes").lower()
    pubkey_auth = pubkey_auth_str in ("yes", "true", "1")

    return SshdConfig(
        port=port,
        permit_root_login=permit_root,
        password_authentication=pass_auth,
        pubkey_authentication=pubkey_auth,
        raw_options=raw_options,
    )
