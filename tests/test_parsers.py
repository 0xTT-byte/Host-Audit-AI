"""Unit and integration tests for Phase 2 pure parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.models.snapshot import ParseWarning
from host_audit_ai.parsers import parse_envelope
from host_audit_ai.parsers.containers_ioc import (
    parse_auth_logs,
    parse_containers,
    parse_ioc_surface,
)
from host_audit_ai.parsers.fs_perms import parse_file_perms, parse_suid_and_caps
from host_audit_ai.parsers.kernel_fw import parse_firewall, parse_sysctl
from host_audit_ai.parsers.network_procs import parse_listening_sockets, parse_processes
from host_audit_ai.parsers.os_meta import parse_os_meta
from host_audit_ai.parsers.packages import parse_packages
from host_audit_ai.parsers.services_cron import parse_cron, parse_systemd_units
from host_audit_ai.parsers.sshd import parse_sshd
from host_audit_ai.parsers.users_sudo import parse_sudoers, parse_users_passwd

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_parse_os_meta() -> None:
    warnings: list[ParseWarning] = []
    raw = (
        'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
        'VERSION_ID="24.04"\n'
        "Linux test-host 6.8.0-40-generic #40-Ubuntu SMP x86_64 GNU/Linux\n"
        "2026-11-24 10:00:00\n"
    )
    meta = parse_os_meta(raw, warnings)
    assert meta.hostname == "test-host"
    assert meta.os_name == "Ubuntu 24.04.1 LTS"
    assert meta.os_version == "24.04"
    assert meta.kernel_release == "6.8.0-40-generic"
    assert meta.architecture == "x86_64"
    assert meta.uptime_seconds == 3600.0
    assert warnings == []


def test_parse_users_passwd_and_warnings() -> None:
    warnings: list[ParseWarning] = []
    raw = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bad_line_missing_fields\n"
        "bad_uid:x:notanint:100::/home/bad:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    )
    users = parse_users_passwd(raw, warnings)
    assert len(users) == 3
    assert users[0].username == "root"
    assert users[0].is_root_equivalent is True
    assert users[1].locked is True
    assert users[2].username == "alice"
    assert users[2].locked is False
    assert len(warnings) == 2
    assert all(w.section_name == "users_passwd" for w in warnings)


def test_parse_sudoers() -> None:
    warnings: list[ParseWarning] = []
    raw = (
        "# comment\n"
        "Defaults env_reset\n"
        "root ALL=(ALL:ALL) ALL\n"
        "deployer ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/vim\n"
        "(ALL) NOPASSWD: ALL\n"
    )
    rules = parse_sudoers(raw, warnings)
    assert len(rules) == 3
    assert rules[0].user_or_group == "root"
    assert rules[0].nopasswd is False
    assert rules[1].user_or_group == "deployer"
    assert rules[1].nopasswd is True
    assert rules[1].commands == ["/usr/bin/systemctl", "/usr/bin/vim"]
    assert rules[2].user_or_group == "current_user"
    assert rules[2].commands == ["ALL"]


def test_parse_sshd_effective_precedence_and_bad_port() -> None:
    warnings: list[ParseWarning] = []
    raw = (
        "port 2222\n"
        "permitrootlogin no\n"
        "passwordauthentication no\n"
        "### FILE: /etc/ssh/sshd_config\n"
        "Port 22\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
    )
    cfg = parse_sshd(raw, warnings)
    assert cfg.port == 2222
    assert cfg.permit_root_login == "no"
    assert cfg.password_authentication is False
    assert warnings == []

    bad_warnings: list[ParseWarning] = []
    bad_cfg = parse_sshd("port invalid_port\n", bad_warnings)
    assert bad_cfg.port == 22
    assert len(bad_warnings) == 1
    assert bad_warnings[0].section_name == "sshd_effective"


def test_parse_listening_sockets_and_processes() -> None:
    warnings: list[ParseWarning] = []
    sock_raw = (
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=842,fd=3))\n'
        'tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=900,fd=6))\n'
        "tcp LISTEN 0 128 :::5432 :::*\n"
        "udp UNCONN 0 0 *:5353 *:* 123/avahi-daemon\n"
    )
    sockets = parse_listening_sockets(sock_raw, warnings)
    assert len(sockets) == 4
    assert sockets[0].local_address == "0.0.0.0"  # noqa: S104
    assert sockets[0].local_port == 22
    assert sockets[0].pid == 842
    assert sockets[0].process_name == "sshd"
    assert sockets[1].local_address == "::"
    assert sockets[1].local_port == 443
    assert sockets[2].local_address == "::"
    assert sockets[2].local_port == 5432
    assert sockets[3].protocol == "udp"
    assert sockets[3].local_port == 5353
    assert sockets[3].pid == 123
    assert sockets[3].process_name == "avahi-daemon"

    proc_raw = "1 0 root 0 0 systemd /sbin/init\n666 1 root 0 0 malware /tmp/evil (deleted)\n"
    procs = parse_processes(proc_raw, warnings)
    assert len(procs) == 2
    assert procs[0].deleted_binary is False
    assert procs[1].pid == 666
    assert procs[1].deleted_binary is True


def test_parse_systemd_and_cron() -> None:
    warnings: list[ParseWarning] = []
    sysd_raw = (
        "=== ACTIVE UNITS ===\n"
        "ssh.service loaded active running OpenSSH\n"
        "=== UNIT FILES ===\n"
        "ssh.service enabled\n"
        "cups.service disabled\n"
    )
    units = parse_systemd_units(sysd_raw, warnings)
    by_name = {u.name: u for u in units}
    assert by_name["ssh.service"].active_state == "active"
    assert by_name["ssh.service"].enabled is True
    assert by_name["cups.service"].enabled is False

    cron_raw = (
        "### FILE: /etc/crontab\n"
        "SHELL=/bin/sh\n"
        "17 * * * * root run-parts /etc/cron.hourly\n"
        "### SPOOL: /var/spool/cron/crontabs/alice\n"
        "*/5 * * * * /tmp/user_task.sh\n"
    )
    crons = parse_cron(cron_raw, warnings)
    assert len(crons) == 2
    assert crons[0].user == "root"
    assert crons[0].source_file == "/etc/crontab"
    assert crons[1].user == "current_user"
    assert crons[1].source_file == "/var/spool/cron/crontabs/alice"


def test_parse_file_perms_and_suid_caps() -> None:
    warnings: list[ParseWarning] = []
    perm_raw = (
        "640 0:42 root:shadow regular file /etc/shadow\n"
        "-rw-r----- 1 root shadow 1234 Nov 24 /etc/shadow\n"
        "777 0:0 /tmp/missing_sticky\n"
        "corrupted_stat_line\n"
    )
    perms = parse_file_perms(perm_raw, warnings)
    assert len(perms) == 2
    assert perms[0].path == "/etc/shadow"
    assert perms[0].permissions == "640"
    assert perms[0].owner == "root"
    assert perms[0].group == "shadow"
    assert perms[0].is_world_writable is False
    assert perms[1].path == "/tmp/missing_sticky"  # noqa: S108
    assert perms[1].is_world_writable is True
    assert len(warnings) == 1

    suid_raw = (
        "4755 0:0 /usr/bin/vim\n"
        "4755 0:0 /usr/bin/sudo\n"
        "=== CAPABILITIES ===\n"
        "/usr/bin/ping cap_net_raw=ep\n"
        "/usr/bin/python3 cap_setuid+ep\n"
    )
    suids, caps = parse_suid_and_caps(suid_raw, warnings)
    assert len(suids) == 2
    assert suids[0].known_gtfobins is True
    assert len(caps) == 2


def test_parse_sysctl_and_firewall() -> None:
    warnings: list[ParseWarning] = []
    sysctls = parse_sysctl("kernel.randomize_va_space = 2\nfs.suid_dumpable: 0\n", warnings)
    assert len(sysctls) == 2
    assert sysctls[0].key == "kernel.randomize_va_space"
    assert sysctls[0].value == "2"

    fw_ufw = parse_firewall("=== UFW STATUS ===\nStatus: inactive\n", warnings)
    assert fw_ufw.backend == "ufw"
    assert fw_ufw.active is False

    fw_docker = parse_firewall(
        "=== IPTABLES RULES ===\n-P INPUT DROP\n"
        "=== IPTABLES DOCKER-USER CHAIN ===\n-A DOCKER-USER -j RETURN\n",
        warnings,
    )
    assert fw_docker.backend == "iptables"
    assert fw_docker.active is True
    assert fw_docker.docker_user_bypasses is True


def test_parse_packages_multi_distro() -> None:
    warnings: list[ParseWarning] = []
    raw = "openssh-server\t1:9.6p1\tamd64\nlinux 6.8.1-arch1-1\nmusl-1.2.5-r0 x86_64 {musl}\n"
    pkgs = parse_packages(raw, warnings)
    assert len(pkgs) == 3
    assert pkgs[0].name == "openssh-server"
    assert pkgs[1].source == "pacman"
    assert pkgs[2].source == "apk"
    assert pkgs[2].name == "musl"


def test_parse_containers_ioc_and_auth() -> None:
    warnings: list[ParseWarning] = []
    cont_raw = (
        "=== RUNTIME SOCKETS ===\n"
        "srw-rw-rw- 1 root root 0 Nov 24 10:00 /var/run/docker.sock\n"
        "=== DOCKER INSPECT ===\n"
        '[{"Id":"abc123def456","Name":"/web","Config":{"Image":"nginx"},'
        '"HostConfig":{"Privileged":true,"NetworkMode":"host","Binds":["/etc:/host_etc:ro"]}}]\n'
    )
    c_state = parse_containers(cont_raw, warnings)
    assert c_state.socket_permissions[0].is_world_writable is True
    assert c_state.running_containers[0].name == "web"
    assert c_state.running_containers[0].privileged is True
    assert c_state.running_containers[0].mounts == ["/etc"]

    bad_json_warnings: list[ParseWarning] = []
    parse_containers("=== DOCKER INSPECT ===\n[bad json]\n", bad_json_warnings)
    assert len(bad_json_warnings) == 1

    ioc_raw = (
        "-rwxr-xr-x 1 root root 500 Nov 24 /tmp/dropper\n"
        "/lib/rootkit.so\n"
        "lrwxrwxrwx 1 root root 0 Nov 24 /proc/888/exe -> /tmp/dropper (deleted)\n"
    )
    ioc = parse_ioc_surface(ioc_raw, warnings)
    assert ioc.temp_executables == ["/tmp/dropper"]  # noqa: S108
    assert ioc.ld_preload_contents == "/lib/rootkit.so"
    assert ioc.deleted_binary_processes[0].pid == 888

    # Multi-directory `ls -la /tmp /var/tmp /dev/shm` format from live Linux hosts
    ls_multi_raw = (
        "=== TEMPORARY AND SHARED MEMORY DIRECTORIES ===\n"
        "/dev/shm:\n"
        "total 4\n"
        "drwxrwxrwt 2 root root 60 Nov 27 12:00 .\n"
        "-rwxr-xr-x 1 root root 32 Nov 27 12:00 dropper.sh\n\n"
        "/tmp:\n"
        "total 4\n"
        "-rwxr-xr-x 1 root root 48 Nov 27 12:00 staged_miner.elf\n"
        "=== PRELOAD AND BOOTSTRAP HOOKS ===\n"
    )
    ioc_multi = parse_ioc_surface(ls_multi_raw, warnings)
    assert ioc_multi.temp_executables == [
        "/dev/shm/dropper.sh",  # noqa: S108
        "/tmp/staged_miner.elf",  # noqa: S108
    ]

    auth = parse_auth_logs(
        "Failed password for root from 1.2.3.4\nAccepted publickey for ubuntu from 1.2.3.5\n",
        warnings,
    )
    assert auth.failed_logins == 1
    assert auth.accepted_logins == 1
    assert auth.root_logins == 1


@pytest.mark.parametrize(
    ("fixture_name", "expected_degraded", "expected_os"),
    [
        ("ubuntu_hardened.raw", False, "Ubuntu 24.04.1 LTS"),
        ("ubuntu_vulnerable.raw", False, "Ubuntu 22.04.4 LTS"),
        ("rhel_degraded.raw", True, "Red Hat Enterprise Linux 9.4 (Plow)"),
    ],
)
def test_parse_envelope_fixtures_end_to_end(
    fixture_name: str, expected_degraded: bool, expected_os: str
) -> None:
    raw_bytes = (FIXTURES_DIR / fixture_name).read_bytes()
    envelope = decode_envelope(raw_bytes, target_uri=f"file://{fixture_name}")
    snapshot = parse_envelope(envelope)

    assert snapshot.degraded_mode is expected_degraded
    assert snapshot.metadata.os_name == expected_os
    assert len(snapshot.users) >= 4
    assert len(snapshot.packages) >= 2

    if fixture_name == "ubuntu_hardened.raw":
        assert snapshot.parse_warnings == []
        assert snapshot.firewall is not None
        assert snapshot.firewall.active is True
    elif fixture_name == "rhel_degraded.raw":
        # Missing critical_perms + malformed passwd + non-zero exit codes
        assert len(snapshot.parse_warnings) >= 5
        assert snapshot.firewall is not None
        assert snapshot.firewall.backend == "nftables"
        assert snapshot.firewall.active is True
