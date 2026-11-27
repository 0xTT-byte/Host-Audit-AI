#!/usr/bin/env bash
# ==============================================================================
# Host Audit AI - Read-Only Agentless Host Security Collector
# Designed for local execution and remote execution over SSH via stdin (bash -s)
# Strictly read-only: NEVER writes temporary files to the target filesystem.
# ==============================================================================

set -u

# Ensure deterministic locale and standard search paths
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# Generate or accept per-run boundary token to prevent delimiter spoofing
if [ -z "${HOST_AUDIT_BOUNDARY:-}" ]; then
    if [ -r /proc/sys/kernel/random/uuid ]; then
        HOST_AUDIT_BOUNDARY=$(tr -dc 'a-f0-9' < /proc/sys/kernel/random/uuid | head -c 32)
    elif command -v od >/dev/null 2>&1 && [ -r /dev/urandom ]; then
        HOST_AUDIT_BOUNDARY=$(od -vN 16 -An -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    fi
    if [ -z "${HOST_AUDIT_BOUNDARY:-}" ] || [ "${#HOST_AUDIT_BOUNDARY}" -lt 16 ]; then
        HOST_AUDIT_BOUNDARY=$(date +%s%N 2>/dev/null | sha256sum 2>/dev/null | head -c 32 || date +%s)
    fi
fi
export HOST_AUDIT_BOUNDARY

COLLECTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u)
HOSTNAME_VAL=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
EUID_VAL=$(id -u 2>/dev/null || echo "1000")

# Emit required format header block
printf 'HOST_AUDIT_FORMAT=1.0.0\n'
printf 'HOST_AUDIT_COLLECTOR_VERSION=0.2.0\n'
printf 'HOST_AUDIT_BOUNDARY=%s\n' "$HOST_AUDIT_BOUNDARY"
printf 'HOST_AUDIT_COLLECTED_AT=%s\n' "$COLLECTED_AT"
printf 'HOST_AUDIT_HOSTNAME=%s\n' "$HOSTNAME_VAL"
printf 'HOST_AUDIT_EUID=%s\n' "$EUID_VAL"

# Helper to run a section command with bounded in-memory streams and anti-spoofing markers
run_section() {
    local name="$1"
    local max_bytes="$2"
    shift 2

    local safe_cmd_label
    safe_cmd_label=$(printf '%s' "$*" | tr '\n\r' '  ' | cut -c 1-128)

    printf '===%s:BEGIN:%s:CMD=%s===\n' "$HOST_AUDIT_BOUNDARY" "$name" "$safe_cmd_label"

    # Execute command, stream stdout through truncation cap, and capture stderr + exit code
    # Zero disk writes: all stream routing uses file descriptors in memory
    exec 3>&1
    local err_and_code
    err_and_code=$(
        {
            {
                {
                    "$@"
                } 2>&5 1>&4
                printf '\n__EXIT__:%d\n' "$?" >&5
            } 4>&1 | {
                local out_chunk
                out_chunk=$(head -c "$((max_bytes + 1))")
                if [ "${#out_chunk}" -gt "$max_bytes" ]; then
                    printf '%s' "${out_chunk:0:$max_bytes}" >&3
                    printf '\n__TRUNCATED__:1\n' >&5
                else
                    printf '%s' "$out_chunk" >&3
                    printf '\n__TRUNCATED__:0\n' >&5
                fi
            }
        } 5>&1
    )
    exec 3>&-

    local exit_code=0 truncated=0 stderr_content=""
    case "$err_and_code" in
        *__TRUNCATED__:1*) truncated=1 ;;
        *) truncated=0 ;;
    esac
    if [[ "$err_and_code" =~ __EXIT__:([0-9]+) ]]; then
        exit_code="${BASH_REMATCH[1]}"
    fi
    stderr_content=$(printf '%s' "$err_and_code" | sed -e 's/__EXIT__:[0-9]*//g' -e 's/__TRUNCATED__:[0-9]*//g')
    stderr_content="${stderr_content#$'\n'}"
    stderr_content="${stderr_content%$'\n'}"

    printf '\n===%s:STDERR:%s===\n' "$HOST_AUDIT_BOUNDARY" "$name"
    if [ -n "$stderr_content" ]; then
        printf '%s\n' "$stderr_content"
    fi
    printf '===%s:END:%s:EXIT=%d:TRUNCATED=%d===\n' "$HOST_AUDIT_BOUNDARY" "$name" "$exit_code" "$truncated"
}

# ------------------------------------------------------------------------------
# Section Implementations
# ------------------------------------------------------------------------------

collect_os_release() {
    if [ -f /etc/os-release ]; then
        cat /etc/os-release
    fi
    uname -a
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl 2>/dev/null || true
    fi
    uptime -s 2>/dev/null || uptime || true
}

collect_users_passwd() {
    getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true
}

collect_users_group() {
    getent group 2>/dev/null || cat /etc/group 2>/dev/null || true
}

collect_shadow_meta() {
    # NEVER dump password hashes! Stat metadata ONLY
    stat -c '%a %u:%g %U:%G %F %n' /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow- 2>/dev/null || true
    ls -ld /etc/shadow /etc/gshadow 2>/dev/null || true
}

collect_sudoers() {
    # Non-interactive sudo check
    sudo -n -l 2>/dev/null || true
    cat /etc/sudoers 2>/dev/null || true
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            if [ -f "$f" ]; then
                echo "### FILE: $f"
                cat "$f" 2>/dev/null || true
            fi
        done
    fi
}

collect_sshd_effective() {
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null || true
    fi
    if [ -f /etc/ssh/sshd_config ]; then
        echo "### FILE: /etc/ssh/sshd_config"
        cat /etc/ssh/sshd_config 2>/dev/null || true
    fi
    if [ -d /etc/ssh/sshd_config.d ]; then
        for f in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$f" ]; then
                echo "### FILE: $f"
                cat "$f" 2>/dev/null || true
            fi
        done
    fi
}

collect_listening_sockets() {
    if command -v ss >/dev/null 2>&1; then
        ss -tulpnH 2>/dev/null || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null || true
    fi
}

collect_processes() {
    if ps -eo pid,ppid,user:32,uid,euid,comm,args --no-headers >/dev/null 2>&1; then
        ps -eo pid,ppid,user:32,uid,euid,comm,args --no-headers 2>/dev/null || true
    else
        ps -ef 2>/dev/null || true
    fi
}

collect_systemd_units() {
    if command -v systemctl >/dev/null 2>&1; then
        echo "=== ACTIVE UNITS ==="
        systemctl list-units --type=service,timer --all --no-pager --no-legend 2>/dev/null || true
        echo "=== UNIT FILES ==="
        systemctl list-unit-files --type=service,timer --no-pager --no-legend 2>/dev/null || true
    fi
}

collect_cron() {
    if [ -f /etc/crontab ]; then
        echo "### FILE: /etc/crontab"
        cat /etc/crontab 2>/dev/null || true
    fi
    if [ -d /etc/cron.d ]; then
        for f in /etc/cron.d/*; do
            if [ -f "$f" ]; then
                echo "### FILE: $f"
                cat "$f" 2>/dev/null || true
            fi
        done
    fi
    echo "=== CRON SPOOLS AND DIRECTORIES ==="
    ls -la /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true
    for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do
        if [ -f "$f" ]; then
            echo "### SPOOL: $f"
            cat "$f" 2>/dev/null || true
        fi
    done
}

collect_suid_sgid() {
    # Scan standard binary and system directories
    find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /opt /etc /tmp /var/tmp /dev/shm -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec stat -c '%a %u:%g %n' {} + 2>/dev/null || true
    if command -v getcap >/dev/null 2>&1; then
        echo "=== CAPABILITIES ==="
        getcap /usr/bin/* /usr/sbin/* /bin/* /sbin/* 2>/dev/null || true
    fi
}

collect_critical_perms() {
    stat -c '%a %u:%g %U:%G %F %n' \
        /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers \
        /etc/ssh/sshd_config /root /root/.ssh /etc/crontab \
        /var/run/docker.sock /run/podman/podman.sock 2>/dev/null || true
    echo "=== WORLD WRITABLE DIRECTORIES WITHOUT STICKY BIT ==="
    find /tmp /var/tmp /dev/shm -maxdepth 3 -xdev -type d -perm -0002 ! -perm -1000 -exec stat -c '%a %u:%g %n' {} + 2>/dev/null || true
}

collect_sysctl() {
    sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.|net\.ipv6\.|kernel\.randomize_va_space|kernel\.kptr_restrict|kernel\.dmesg_restrict|kernel\.yama\.ptrace_scope|kernel\.unprivileged_bpf_disabled|fs\.protected_|fs\.suid_dumpable)' || true
}

collect_firewall() {
    if command -v nft >/dev/null 2>&1; then
        echo "=== NFTABLE RULESET ==="
        nft list ruleset 2>/dev/null || true
    fi
    if command -v ufw >/dev/null 2>&1; then
        echo "=== UFW STATUS ==="
        ufw status verbose 2>/dev/null || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        echo "=== IPTABLES RULES ==="
        iptables -S 2>/dev/null || true
        echo "=== IPTABLES DOCKER-USER CHAIN ==="
        iptables -S DOCKER-USER 2>/dev/null || true
    fi
}

collect_packages() {
    local os_id=""
    if [ -f /etc/os-release ]; then
        os_id=$(grep -E '^(ID|ID_LIKE)=' /etc/os-release 2>/dev/null || true)
    fi

    case "$os_id" in
        *rhel*|*fedora*|*centos*|*rocky*|*alma*|*amzn*)
            if command -v rpm >/dev/null 2>&1; then
                rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null || true
                return 0
            fi
            ;;
        *debian*|*ubuntu*)
            if command -v dpkg-query >/dev/null 2>&1 && [ -s /var/lib/dpkg/status ]; then
                dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null || true
                return 0
            fi
            ;;
        *arch*)
            if command -v pacman >/dev/null 2>&1; then
                pacman -Q 2>/dev/null || true
                return 0
            fi
            ;;
        *alpine*)
            if command -v apk >/dev/null 2>&1; then
                apk info -vv 2>/dev/null || true
                return 0
            fi
            ;;
    esac

    # Generic fallbacks if distro heuristics didn't match or primary query was empty
    if [ -s /var/lib/dpkg/status ] && command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null || true
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Q 2>/dev/null || true
    elif command -v apk >/dev/null 2>&1; then
        apk info -vv 2>/dev/null || true
    fi
}

collect_containers() {
    echo "=== RUNTIME SOCKETS ==="
    ls -la /var/run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock 2>/dev/null || true
    if command -v docker >/dev/null 2>&1; then
        echo "=== DOCKER PS ==="
        docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null || true
        echo "=== DOCKER INSPECT ==="
        docker ps -q 2>/dev/null | xargs -r docker inspect 2>/dev/null || true
    fi
    if command -v podman >/dev/null 2>&1; then
        echo "=== PODMAN PS ==="
        podman ps -a 2>/dev/null || true
    fi
    if command -v crictl >/dev/null 2>&1; then
        echo "=== CRICTL PS ==="
        crictl ps 2>/dev/null || true
    fi
}

collect_auth_logs() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u ssh -u sshd -n 500 --no-pager 2>/dev/null || true
    elif [ -r /var/log/auth.log ]; then
        tail -n 500 /var/log/auth.log 2>/dev/null || true
    elif [ -r /var/log/secure ]; then
        tail -n 500 /var/log/secure 2>/dev/null || true
    fi
}

collect_ioc_surface() {
    echo "=== TEMPORARY AND SHARED MEMORY DIRECTORIES ==="
    ls -la /tmp /var/tmp /dev/shm 2>/dev/null || true
    echo "=== PRELOAD AND BOOTSTRAP HOOKS ==="
    ls -la /etc/ld.so.preload /etc/rc.local 2>/dev/null || true
    if [ -f /etc/ld.so.preload ]; then
        cat /etc/ld.so.preload 2>/dev/null || true
    fi
    echo "=== SSH AUTHORIZED KEYS FILES ==="
    find /root /home -maxdepth 3 -name authorized_keys -exec stat -c '%a %u:%g %n' {} + 2>/dev/null || true
    echo "=== PROCESSES WITH DELETED EXECUTABLES ==="
    ls -l /proc/*/exe 2>/dev/null | grep deleted || true
}

# ------------------------------------------------------------------------------
# Main Collection Execution
# ------------------------------------------------------------------------------

# Default max section sizes (bytes): 512 KiB default, 2 MiB for packages/containers
DEFAULT_MAX=524288
LARGE_MAX=2097152

run_section "os_release"         "$DEFAULT_MAX" collect_os_release
run_section "users_passwd"       "$DEFAULT_MAX" collect_users_passwd
run_section "users_group"        "$DEFAULT_MAX" collect_users_group
run_section "shadow_meta"        "$DEFAULT_MAX" collect_shadow_meta
run_section "sudoers"            "$DEFAULT_MAX" collect_sudoers
run_section "sshd_effective"     "$DEFAULT_MAX" collect_sshd_effective
run_section "listening_sockets"  "$DEFAULT_MAX" collect_listening_sockets
run_section "processes"          "$DEFAULT_MAX" collect_processes
run_section "systemd_units"      "$DEFAULT_MAX" collect_systemd_units
run_section "cron"               "$DEFAULT_MAX" collect_cron
run_section "suid_sgid"          "$DEFAULT_MAX" collect_suid_sgid
run_section "critical_perms"     "$DEFAULT_MAX" collect_critical_perms
run_section "sysctl"             "$DEFAULT_MAX" collect_sysctl
run_section "firewall"           "$DEFAULT_MAX" collect_firewall
run_section "packages"           "$LARGE_MAX"   collect_packages
run_section "containers"         "$LARGE_MAX"   collect_containers
run_section "auth_logs"          "$DEFAULT_MAX" collect_auth_logs
run_section "ioc_surface"        "$DEFAULT_MAX" collect_ioc_surface
