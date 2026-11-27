#!/usr/bin/env bash
set -euo pipefail

# Runtime /dev/shm is mounted fresh as tmpfs, so seed the harmless IOC script on startup.
printf '#!/bin/sh\necho "harmless shm dropper stub"\n' > /dev/shm/dropper.sh
chmod 0755 /dev/shm/dropper.sh

install_auth_keys() {
    local user="$1"
    local src_file="$2"
    local ssh_dir="/home/${user}/.ssh"
    local dest_file="${ssh_dir}/authorized_keys"

    mkdir -p "$ssh_dir"
    cp "$src_file" "$dest_file"
    chown -R "${user}:${user}" "$ssh_dir"
    chmod 0700 "$ssh_dir"
    chmod 0600 "$dest_file"
}

if [ -f /etc/audit-keys/audituser.pub ]; then
    install_auth_keys "audituser" /etc/audit-keys/audituser.pub
elif [ -n "${AUDITUSER_PUBKEY:-}" ]; then
    mkdir -p /home/audituser/.ssh
    printf '%s\n' "$AUDITUSER_PUBKEY" > /home/audituser/.ssh/authorized_keys
    chown -R audituser:audituser /home/audituser/.ssh
    chmod 0700 /home/audituser/.ssh
    chmod 0600 /home/audituser/.ssh/authorized_keys
fi

if [ -f /etc/audit-keys/auditmcp_authorized_keys ]; then
    install_auth_keys "auditmcp" /etc/audit-keys/auditmcp_authorized_keys
elif [ -n "${AUDITMCP_AUTHORIZED_KEYS:-}" ]; then
    mkdir -p /home/auditmcp/.ssh
    printf '%s\n' "$AUDITMCP_AUTHORIZED_KEYS" > /home/auditmcp/.ssh/authorized_keys
    chown -R auditmcp:auditmcp /home/auditmcp/.ssh
    chmod 0700 /home/auditmcp/.ssh
    chmod 0600 /home/auditmcp/.ssh/authorized_keys
fi

mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
