#!/usr/bin/bash
# Audit-collect.sh - read-only, run as root 
OUT=/root/audit-$(hostname)-$(date +%F); mkdir -p "$OUT"; cd"$OUT"

run() { local n=$1; shift; { echo "### CMD: $*"; "$@" 2>&1; } > "$n.txt"; }

run net-listen      ss -tulpnH
run docker-ps       docker ps --format '{{.Name}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'
run docker-inspect  bash -c 'docker ps -q | xargs docker inspect --format "{{.Name}} priv={{.HostConfig.Privileged}} user={{.Config.User}} netmode={{.HostConfig.NetworkMode}} caps={{.HostConfig.CapAdd}} binds{{.HostConfig.Binds}}"'
run fw-nft          nft list ruleset 
run fw-docker-user  iptanles -S DOCKER-USER
run sshd            sshd -T
run users           bash -c 'getent passwd; echo; awk -F: "(\$3==0)" /etc/passwd; echo; lastlog | head -50'
run sudoers         bash -c 'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null'
run suid            find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 
run world-writable  find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*'
run cron-systemd    bash -c 'ls -la /etc/cron* /var/spool/cron 2>/dev/null; systemctl list-unit-files --state=enabled'
run caps            getcap -r / 2>/dev/null
run patches         bash -c 'dnf updateinfo list security 2>/dev/null || apt list --upgradable 2>/dev/null; uname -r'
run secrets-paths   grep -rIlE '(pass(word)?|secret|token|api[_-]?key)\s*[=:]' /opt /srv /etc /home --exclude-dir=.git
run lynis           lynis audit system --quick --no-colors 
