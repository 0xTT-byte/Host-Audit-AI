from pathlib import Path
from typing import Any
from host_audit.schema import Finding


def check_ssh_and_users(collect_dir: Path, baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    auth_cfg = baseline.get("auth", {})

    # 1. sshd -T checks
    sshd_file = collect_dir / "sshd.txt"
    if sshd_file.exists():
        cfg: dict[str, str] = {}
        for line in sshd_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("###") or " " not in line:
                continue
            k, v = line.split(" ", 1)
            cfg[k.lower()] = v.strip().lower()

        root_login = cfg.get("permitrootlogin", "unknown")
        allowed_root_login = auth_cfg.get("permit_root_login", ["no", "prohibit-password"])
        if root_login not in allowed_root_login:
            findings.append(
                Finding(
                    rule_id="SSH-001",
                    domain="ssh",
                    title=f"Root SSH login permitted ({root_login})",
                    target="sshd:permitrootlogin",
                    evidence=f"permitrootlogin {root_login}",
                    why_it_matters="Direct root SSH access eliminates individual accountability and enables brute-force attacks directly targeting UID 0.",
                    verify_cmd="sshd -T | grep -i permitrootlogin",
                    remediation_hint="Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config and reload sshd.",
                    reachability=3,
                    privilege_gain=3,
                    ease=2,
                )
            )

        pass_auth = cfg.get("passwordauthentication", "unknown")
        if pass_auth == "yes" and not auth_cfg.get("allow_password_auth", False):
            findings.append(
                Finding(
                    rule_id="SSH-002",
                    domain="ssh",
                    title="SSH PasswordAuthentication is enabled",
                    target="sshd:passwordauthentication",
                    evidence=f"passwordauthentication {pass_auth}",
                    why_it_matters="Password-based authentication leaves the SSH service vulnerable to credential stuffing, dictionary attacks, and weak passwords.",
                    verify_cmd="sshd -T | grep -i passwordauthentication",
                    remediation_hint="Configure SSH keys for authorized users and set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
                    reachability=3,
                    privilege_gain=2,
                    ease=2,
                )
            )

        try:
            max_tries = int(cfg.get("maxauthtries", "6"))
        except ValueError:
            max_tries = 6

        allowed_max_tries = auth_cfg.get("max_auth_tries", 4)
        if max_tries > allowed_max_tries:
            findings.append(
                Finding(
                    rule_id="SSH-003",
                    domain="ssh",
                    title=f"SSH MaxAuthTries is high ({max_tries})",
                    target="sshd:maxauthtries",
                    evidence=f"maxauthtries {max_tries}",
                    why_it_matters="A high MaxAuthTries value allows more authentication attempts per TCP connection, aiding credential guessing tools.",
                    verify_cmd="sshd -T | grep -i maxauthtries",
                    remediation_hint=f"Set 'MaxAuthTries {allowed_max_tries}' in /etc/ssh/sshd_config.",
                    reachability=3,
                    privilege_gain=1,
                    ease=2,
                )
            )

        if auth_cfg.get("require_allow_list", True) and "allowusers" not in cfg and "allowgroups" not in cfg:
            findings.append(
                Finding(
                    rule_id="SSH-004",
                    domain="ssh",
                    title="No AllowUsers or AllowGroups restriction configured in sshd",
                    target="sshd:allowusers",
                    evidence="allowusers/allowgroups absent from sshd -T",
                    why_it_matters="Any local system user with a valid login shell can attempt SSH authentication.",
                    verify_cmd="sshd -T | grep -E 'allow(users|groups)'",
                    remediation_hint="Define 'AllowUsers <user>' or 'AllowGroups <group>' in /etc/ssh/sshd_config to restrict SSH login privileges.",
                    reachability=3,
                    privilege_gain=2,
                    ease=1,
                )
            )

    # 2. Rogue UID 0 check in users.txt
    users_file = collect_dir / "users.txt"
    if users_file.exists():
        allowed_uid0 = set(auth_cfg.get("uid0_allowed", ["root"]))
        for line in users_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                username = parts[0]
                if username not in allowed_uid0:
                    findings.append(
                        Finding(
                            rule_id="AUTH-001",
                            domain="ssh",
                            title=f"Unauthorized UID 0 account detected: {username}",
                            target=f"user:{username}",
                            evidence=line,
                            why_it_matters=f"Account '{username}' has UID 0, granting full unrestricted root authority on the host.",
                            verify_cmd="awk -F: '($3==0){print}' /etc/passwd",
                            remediation_hint=f"Investigate origin of account '{username}', lock it (usermod -L {username}), and remove if unauthorized.",
                            reachability=2,
                            privilege_gain=3,
                            ease=3,
                        )
                    )

    return findings
