#!/usr/bin/env bash
# Hardened read-only SSH forced-command wrapper for host-audit-ai (Phase 4).
# Installed on audited targets via authorized_keys:
#   command="/usr/local/bin/host-audit-wrapper",restrict <pubkey>
set -euo pipefail
set -f

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

readonly MAX_OUTPUT_BYTES=32768

deny() {
    local reason="$1"
    if command -v logger >/dev/null 2>&1; then
        logger -t host-audit-wrapper "REJECTED: ${reason}" >/dev/null 2>&1 || true
    fi
    printf 'host-audit-wrapper: rejected (%s)\n' "$reason" >&2
    exit 126
}

raw_cmd="${SSH_ORIGINAL_COMMAND:-}"
if [[ -z "$raw_cmd" ]]; then
    deny "empty SSH_ORIGINAL_COMMAND"
fi

# Reject newlines, carriage returns, NULs, parent traversal, and shell metacharacters.
if [[ "$raw_cmd" == *$'\n'* || "$raw_cmd" == *$'\r'* ]]; then
    deny "newline characters not permitted"
fi
if [[ "$raw_cmd" == *".."* ]]; then
    deny "path traversal sequence '..' not permitted"
fi
if [[ "$raw_cmd" =~ [\;\|\&\$\`\(\)\<\>\\\'\"\*\{\}\[\]\~\!] ]]; then
    deny "disallowed shell metacharacter"
fi

# Split strictly on ASCII spaces without glob expansion (set -f is active).
IFS=' ' read -r -a args <<< "$raw_cmd"
if (( ${#args[@]} == 0 )); then
    deny "missing command verb"
fi

verb="${args[0]}"

cap_output() {
    head -c "$MAX_OUTPUT_BYTES"
}

validate_read_config_allowlist() {
    local canon="$1"

    # Explicit high-sensitivity denylist first.
    case "$canon" in
        /etc/shadow|/etc/shadow-*|/etc/gshadow|/etc/gshadow-*|/etc/sudoers|/etc/sudoers.d/*)
            return 1
            ;;
        /proc/*|/sys/*|/dev/*)
            return 1
            ;;
        *.key|*.pem)
            return 1
            ;;
    esac
    if [[ "$canon" =~ /id_[^/]+$ ]]; then
        return 1
    fi

    # Strict allowlist of read-only host configuration files.
    case "$canon" in
        /etc/ssh/sshd_config|/etc/crontab|/etc/sysctl.conf|/etc/ld.so.preload|/etc/nftables.conf|/etc/ufw/ufw.conf|/etc/ufw/before.rules|/etc/ufw/after.rules)
            return 0
            ;;
    esac
    if [[ "$canon" =~ ^/etc/ssh/sshd_config\.d/[A-Za-z0-9._-]+\.conf$ ]]; then
        return 0
    fi
    if [[ "$canon" =~ ^/etc/cron\.d/[A-Za-z0-9._-]+$ ]]; then
        return 0
    fi
    if [[ "$canon" =~ ^/etc/sysctl\.d/[A-Za-z0-9._-]+\.conf$ ]]; then
        return 0
    fi
    if [[ "$canon" =~ ^/etc/systemd/system/[A-Za-z0-9@._-]+\.(service|timer)$ ]]; then
        return 0
    fi

    return 1
}

case "$verb" in
    ping)
        if (( ${#args[@]} != 1 )); then
            deny "ping takes no arguments"
        fi
        printf 'host-audit-wrapper:ok\n'
        ;;

    inspect-unit)
        if (( ${#args[@]} != 2 )); then
            deny "inspect-unit requires <unit_name>"
        fi
        unit="${args[1]}"
        if [[ ! "$unit" =~ ^[A-Za-z0-9@._-]{1,128}$ ]]; then
            deny "invalid systemd unit name"
        fi
        if ! command -v systemctl >/dev/null 2>&1; then
            deny "systemctl not installed"
        fi
        {
            systemctl status --no-pager --full -- "$unit" 2>&1 || true
            printf '\n--- UNIT FILE ---\n'
            systemctl cat --no-pager -- "$unit" 2>&1 || true
        } | cap_output
        ;;

    read-config)
        if (( ${#args[@]} != 4 )); then
            deny "read-config requires <path> <start_line> <max_lines>"
        fi
        req_path="${args[1]}"
        start_line="${args[2]}"
        max_lines="${args[3]}"

        if [[ ! "$req_path" =~ ^/[A-Za-z0-9._/+@-]{1,256}$ ]]; then
            deny "invalid config path syntax"
        fi
        if [[ ! "$start_line" =~ ^[0-9]+$ || ! "$max_lines" =~ ^[0-9]+$ ]]; then
            deny "start_line and max_lines must be positive integers"
        fi
        if (( start_line < 1 || max_lines < 1 || max_lines > 120 )); then
            deny "line slice out of bounds (start >= 1, 1 <= max_lines <= 120)"
        fi

        if ! canon="$(realpath -e -- "$req_path" 2>/dev/null)"; then
            deny "config path does not exist or cannot be resolved"
        fi
        if ! validate_read_config_allowlist "$canon"; then
            deny "config path outside read-only allowlist"
        fi

        end_line=$(( start_line + max_lines - 1 ))
        sed -n "${start_line},${end_line}p" -- "$canon" | cap_output
        ;;

    check-binary)
        if (( ${#args[@]} != 2 )); then
            deny "check-binary requires <path>"
        fi
        bin_path="${args[1]}"
        if [[ ! "$bin_path" =~ ^/[A-Za-z0-9._/+@-]{1,256}$ ]]; then
            deny "invalid binary path syntax"
        fi
        if ! canon="$(realpath -e -- "$bin_path" 2>/dev/null)"; then
            deny "binary path does not exist"
        fi
        {
            printf 'realpath: %s\n' "$canon"
            stat -c 'stat: %a %u:%g %U:%G %F %n' -- "$canon"
            if command -v getcap >/dev/null 2>&1; then
                caps="$(getcap -- "$canon" 2>/dev/null || true)"
                printf 'caps: %s\n' "${caps:-none}"
            fi
        } | cap_output
        ;;

    check-port)
        if (( ${#args[@]} != 3 )); then
            deny "check-port requires <tcp|udp> <port>"
        fi
        proto="${args[1]}"
        port="${args[2]}"
        if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
            deny "protocol must be tcp or udp"
        fi
        if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
            deny "port must be an integer between 1 and 65535"
        fi
        if command -v ss >/dev/null 2>&1; then
            ss -H -nlp "--${proto}" "sport = :${port}" 2>&1 | cap_output
        elif command -v netstat >/dev/null 2>&1; then
            netstat -nlp 2>&1 | grep -E "^${proto}[[:space:]].*:${port}[[:space:]]" | cap_output || true
        else
            deny "neither ss nor netstat is available"
        fi
        ;;

    check-pkg)
        if (( ${#args[@]} != 2 )); then
            deny "check-pkg requires <package_name>"
        fi
        pkg="${args[1]}"
        if [[ ! "$pkg" =~ ^[A-Za-z0-9.+_-]{1,128}$ ]]; then
            deny "invalid package name"
        fi
        if command -v dpkg-query >/dev/null 2>&1; then
            { dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' -- "$pkg" 2>&1 || true; } | cap_output
        elif command -v rpm >/dev/null 2>&1; then
            { rpm -q -- "$pkg" 2>&1 || true; } | cap_output
        elif command -v pacman >/dev/null 2>&1; then
            { pacman -Q -- "$pkg" 2>&1 || true; } | cap_output
        elif command -v apk >/dev/null 2>&1; then
            { apk info -e -v -- "$pkg" 2>&1 || true; } | cap_output
        else
            deny "no supported package manager found"
        fi
        ;;

    *)
        deny "unsupported verb '${verb}'"
        ;;
esac
