#!/usr/bin/env bash
# collect/audit-collect.sh - Agentless read-only security collector
# Designed to run remotely via SSH with zero stdout pollution for clean tar streaming.

set -o pipefail

AUDIT_OUT="${AUDIT_OUT:-/tmp/audit-latest}"
mkdir -p "$AUDIT_OUT"
chmod 700 "$AUDIT_OUT" 2>/dev/null || true

# 1. Network listeners (numeric, TCP & UDP, processes)
if command -v ss >/dev/null 2>&1; then
    ss -tulpnH > "$AUDIT_OUT/net-listen.txt" 2>&1 || true
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn > "$AUDIT_OUT/net-listen.txt" 2>&1 || true
else
    : > "$AUDIT_OUT/net-listen.txt"
fi

# 2. Docker process list
if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' > "$AUDIT_OUT/docker-ps.txt" 2>&1 || true
else
    : > "$AUDIT_OUT/docker-ps.txt"
fi

# 3. Docker container inspect (raw JSON array via docker ps -q | xargs -r docker inspect)
if command -v docker >/dev/null 2>&1; then
    docker ps -q 2>/dev/null | xargs -r docker inspect > "$AUDIT_OUT/docker-inspect.json" 2>/dev/null || true
fi
if [ ! -s "$AUDIT_OUT/docker-inspect.json" ]; then
    echo "[]" > "$AUDIT_OUT/docker-inspect.json"
fi

# 4. Firewall: nftables ruleset
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$AUDIT_OUT/fw-nft.txt" 2>&1 || true
else
    : > "$AUDIT_OUT/fw-nft.txt"
fi

# 5. Firewall: iptables DOCKER-USER chain
if command -v iptables >/dev/null 2>&1; then
    iptables -S DOCKER-USER > "$AUDIT_OUT/fw-docker-user.txt" 2>&1 || true
else
    : > "$AUDIT_OUT/fw-docker-user.txt"
fi

# 6. SSH Daemon configuration
if command -v sshd >/dev/null 2>&1; then
    sshd -T > "$AUDIT_OUT/sshd.txt" 2>&1 || true
elif [ -f /etc/ssh/sshd_config ]; then
    grep -vE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config > "$AUDIT_OUT/sshd.txt" 2>&1 || true
else
    : > "$AUDIT_OUT/sshd.txt"
fi

# 7. System users
{
    getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true
} > "$AUDIT_OUT/users.txt"

# 8. Sudoers configuration
{
    cat /etc/sudoers 2>/dev/null || true
    cat /etc/sudoers.d/* 2>/dev/null || true
} > "$AUDIT_OUT/sudoers.txt"

# 9. SUID / SGID binaries
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$AUDIT_OUT/suid.txt" || true

# 10. File capabilities
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null > "$AUDIT_OUT/caps.txt" || true
else
    : > "$AUDIT_OUT/caps.txt"
fi

# 11. Cron jobs and enabled systemd units
{
    echo "=== CRON DIRECTORIES ==="
    ls -la /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true
    echo "=== SYSTEMD ENABLED UNITS ==="
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-unit-files --state=enabled 2>/dev/null || true
    fi
} > "$AUDIT_OUT/cron-systemd.txt" 2>&1

# 12. Running processes with deleted executables
# shellcheck disable=SC2010
ls -l /proc/*/exe 2>/dev/null | grep deleted > "$AUDIT_OUT/deleted-procs.txt" || true
