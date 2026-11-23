from pathlib import Path
from engine.schema import Finding


def check_ssh_and_users(collect_dir: Path, baseline: dict) -> list[Finding]:
    findings: list[Finding] = []
    auth_cfg = baseline["auth"]

    # 1. sshd -T checks
    sshd_file = collect_dir / "sshd.txt"
    if sshd_file.exists():
        cfg: dict[str, str] = {}
        for line in sshd_file.read_text(errors="replace").splitlines():
            if line.startswith("###") or " " not in line:
                continue
            k, v = line.strip().split(" ", 1)
            cfg[k.lower()] = v.strip().lower()

        root_login = cfg.get("permitrootlogin", "unknown")
        if root_login not in auth_cfg["permit_root_login"]:
            findings.append(
                Finding(
                    rule_id="SSH-001",
                    domain="ssh",
                    title=f"Root SSH login permitted ({root_login})",
                    target="sshd:permitrootlogin",
                    evidence=f"permitrootlogin {root_login}",
                    why_it_matters="Direct root SSH access eliminates accountability and enables direct brute-force against UID 0.",
                    verify_cmd="sshd -T | grep -i permitrootlogin",
                    remediation_hint="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.",
                    reachability=3,
                    privilege_gain=3,
                    ease=2,
                )
            )

        pass_auth = cfg.get("passwordauthentication", "unknown")
        if pass_auth == "yes" and not auth_cfg["allow_password_auth"]:
            findings.append(
                Finding(
                    rule_id="SSH-002",
                    domain="ssh",
                    title="SSH PasswordAuthentication is enabled",
                    target="sshd:passwordauthentication",
                    evidence=f"passwordauthentication {pass_auth}",
                    why_it_matters="Allows automated credential stuffing and brute-force attacks from the internet.",
                    verify_cmd="sshd -T | grep -i passwordauthentication",
                    remediation_hint="Set 'PasswordAuthentication no' after confirming key-based login works.",
                    reachability=3,
                    privilege_gain=2,
                    ease=2,
                )
            )

        max_tries = int(cfg.get("maxauthtries", "6"))
        if max_tries > auth_cfg["max_auth_tries"]:
            findings.append(
                Finding(
                    rule_id="SSH-003",
                    domain="ssh",
                    title=f"SSH MaxAuthTries is high ({max_tries})",
                    target="sshd:maxauthtries",
                    evidence=f"maxauthtries {max_tries}",
                    why_it_matters="Allows multiple password/key guesses per single TCP connection before disconnecting.",
                    verify_cmd="sshd -T | grep -i maxauthtries",
                    remediation_hint=f"Set 'MaxAuthTries {auth_cfg['max_auth_tries']}' in sshd_config.",
                    reachability=3,
                    privilege_gain=1,
                    ease=2,
                )
            )

        if auth_cfg.get("require_allow_list") and "allowusers" not in cfg and "allowgroups" not in cfg:
            findings.append(
                Finding(
                    rule_id="SSH-004",
                    domain="ssh",
                    title="No AllowUsers or AllowGroups restriction configured in sshd",
                    target="sshd:allowusers",
                    evidence="allowusers/allowgroups absent from sshd -T",
                    why_it_matters="Any system or newly created user with a valid shell can attempt SSH authentication.",
                    verify_cmd="sshd -T | grep -E 'allow(users|groups)'",
                    remediation_hint="Add 'AllowUsers <your-admin-user>' to /etc/ssh/sshd_config.",
                    reachability=3,
                    privilege_gain=2,
                    ease=1,
                )
            )

    # 2. Rogue UID 0 check
    users_file = collect_dir / "users.txt"
    if users_file.exists():
        allowed_uid0 = set(auth_cfg["uid0_allowed"])
        for line in users_file.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 7 and parts[2] == "0":
                username = parts[0]
                if username not in allowed_uid0:
                    findings.append(
                        Finding(
                            rule_id="AUTH-001",
                            domain="ssh",
                            title=f"Unauthorized UID 0 account detected: {username}",
                            target=f"user:{username}",
                            evidence=line.strip(),
                            why_it_matters="Any account with UID 0 has full root privileges regardless of its username.",
                            verify_cmd="awk -F: '($3==0){print}' /etc/passwd",
                            remediation_hint=f"Investigate origin of '{username}', lock account (usermod -L), and remove if unauthorized.",
                            reachability=2,
                            privilege_gain=3,
                            ease=3,
                        )
                    )

    return findings