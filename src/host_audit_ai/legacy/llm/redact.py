"""Redaction module for scrubbing sensitive identifiers from audit evidence.

Replaces usernames, hostnames, IPs, and secret/key-like strings with stable placeholders
(HOST_1, IP_3, USER_2, KEY_1, ...), strips control characters, and truncates evidence to ~600 chars.
Maintains a reversible mapping so values can be restored at render time.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Pattern

if TYPE_CHECKING:
    from host_audit.schema import Finding

# Control character pattern: ASCII 0x00-0x1F and 0x7F-0x9F except \n and \t
CONTROL_CHAR_RE: Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# IP address patterns
IPV4_RE: Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)
IPV6_RE: Pattern[str] = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?::[0-9a-fA-F]{1,4}){1,7}\b"
    r"|\b::1\b|\bfe80::[0-9a-fA-F:]+\b"
)

# Key/Secret patterns
PRIVATE_KEY_RE: Pattern[str] = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]+PRIVATE KEY-----"
)
SSH_PUBKEY_RE: Pattern[str] = re.compile(
    r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9]+)\s+[A-Za-z0-9+/=]{40,}(?:\s+\S+)?"
)
SECRET_ASSIGN_RE: Pattern[str] = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|bearer|auth[_-]?token)"
    r"(\s*[:=]\s*[\"']?)([^\s,;'\"]{4,})([\"']?)"
)
HEX_SECRET_RE: Pattern[str] = re.compile(
    r"(?<![a-zA-Z0-9_])[a-fA-F0-9]{32,64}(?![a-zA-Z0-9_])"
)

# Hostname patterns
FQDN_RE: Pattern[str] = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:local|internal|lan|corp|home|internal\.net|com|net|org|io|dev)\b"
)
HOST_LABEL_RE: Pattern[str] = re.compile(
    r"(?i)\b(?:host(?:name)?|node|server)\s*[:=]\s*([a-zA-Z0-9_.-]+)"
)

# Username patterns
USER_LABEL_RE: Pattern[str] = re.compile(
    r"(?i)\b(?:user(?:name)?|login|runas|owner|sudoers?)\s*[:= ]\s*([a-zA-Z0-9_.-]+)"
)
HOME_USER_RE: Pattern[str] = re.compile(
    r"(?:/home/|/Users/|/var/mail/)([a-zA-Z0-9_.-]+)"
)

COMMON_SYSTEM_USERS = {
    "root", "ubuntu", "admin", "postgres", "mysql", "deploy", "debian",
    "ec2-user", "centos", "nginx", "www-data", "redis", "docker", "operator",
}

PLACEHOLDER_RE: Pattern[str] = re.compile(r"\b(HOST_\d+|IP_\d+|USER_\d+|KEY_\d+)\b")


def strip_control_chars(text: str) -> str:
    """Remove ASCII control characters except newline and tab."""
    return CONTROL_CHAR_RE.sub("", text)


def truncate_evidence(text: str, max_chars: int = 600) -> str:
    """Truncate evidence text to approximately max_chars."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "... [truncated]"


class Redactor:
    """Stateful redactor maintaining reversible mappings between values and stable placeholders."""

    def __init__(
        self,
        known_hosts: list[str] | None = None,
        known_users: list[str] | None = None,
        known_ips: list[str] | None = None,
    ):
        self.placeholder_to_val: dict[str, str] = {}
        self.val_to_placeholder: dict[str, str] = {}
        self._counts: dict[str, int] = {
            "KEY": 0,
            "IP": 0,
            "HOST": 0,
            "USER": 0,
        }
        self.unknown_placeholders: int = 0

        # Seed KNOWN values first before heuristic passes
        if known_hosts:
            for h in sorted(set(known_hosts), key=len, reverse=True):
                self._get_or_create("HOST", h)
        if known_ips:
            for ip in sorted(set(known_ips), key=len, reverse=True):
                self._get_or_create("IP", ip)
        if known_users:
            for u in sorted(set(known_users), key=len, reverse=True):
                self._get_or_create("USER", u)

    def _get_or_create(self, kind: str, value: str) -> str:
        clean_val = value.strip()
        if not clean_val:
            return value
        if clean_val in self.val_to_placeholder:
            return self.val_to_placeholder[clean_val]
        self._counts[kind] += 1
        placeholder = f"{kind}_{self._counts[kind]}"
        self.val_to_placeholder[clean_val] = placeholder
        self.placeholder_to_val[placeholder] = clean_val
        return placeholder

    def redact(self, text: str, max_chars: int = 600) -> str:
        """Sanitize text: replace secrets/IPs/hosts/users and truncate."""
        cleaned = text

        # 1. Private keys
        def _replace_priv_key(m: re.Match[str]) -> str:
            return self._get_or_create("KEY", m.group(0))

        cleaned = PRIVATE_KEY_RE.sub(_replace_priv_key, cleaned)

        # 2. SSH public keys
        def _replace_ssh_pubkey(m: re.Match[str]) -> str:
            return self._get_or_create("KEY", m.group(0))

        cleaned = SSH_PUBKEY_RE.sub(_replace_ssh_pubkey, cleaned)

        # 3. Explicit secrets (password=..., api_key=...)
        def _replace_secret_assign(m: re.Match[str]) -> str:
            prefix = m.group(1) + m.group(2)
            val = m.group(3)
            suffix = m.group(4)
            ph = self._get_or_create("KEY", val)
            return f"{prefix}{ph}{suffix}"

        cleaned = SECRET_ASSIGN_RE.sub(_replace_secret_assign, cleaned)

        # 4. Long hex strings (potential API keys / hashes / tokens)
        def _replace_hex(m: re.Match[str]) -> str:
            return self._get_or_create("KEY", m.group(0))

        cleaned = HEX_SECRET_RE.sub(_replace_hex, cleaned)

        # 5. IP addresses (IPv4 & IPv6)
        def _replace_ipv4(m: re.Match[str]) -> str:
            return self._get_or_create("IP", m.group(0))

        cleaned = IPV4_RE.sub(_replace_ipv4, cleaned)

        def _replace_ipv6(m: re.Match[str]) -> str:
            return self._get_or_create("IP", m.group(0))

        cleaned = IPV6_RE.sub(_replace_ipv6, cleaned)

        # 6. FQDNs and labeled hostnames
        def _replace_fqdn(m: re.Match[str]) -> str:
            return self._get_or_create("HOST", m.group(0))

        cleaned = FQDN_RE.sub(_replace_fqdn, cleaned)

        def _replace_host_label(m: re.Match[str]) -> str:
            raw_host = m.group(1)
            ph = self._get_or_create("HOST", raw_host)
            return m.group(0).replace(raw_host, ph)

        cleaned = HOST_LABEL_RE.sub(_replace_host_label, cleaned)

        # 7. Usernames (/home/<user>, user=..., and common usernames)
        def _replace_home_user(m: re.Match[str]) -> str:
            user = m.group(1)
            ph = self._get_or_create("USER", user)
            return m.group(0).replace(user, ph)

        cleaned = HOME_USER_RE.sub(_replace_home_user, cleaned)

        def _replace_user_label(m: re.Match[str]) -> str:
            raw_user = m.group(1)
            ph = self._get_or_create("USER", raw_user)
            return m.group(0).replace(raw_user, ph)

        cleaned = USER_LABEL_RE.sub(_replace_user_label, cleaned)

        # 8. Known and common usernames as standalone words (longest first)
        all_user_keys = set(COMMON_SYSTEM_USERS)
        for val, ph in self.val_to_placeholder.items():
            if ph.startswith("USER_"):
                all_user_keys.add(val)

        for u in sorted(all_user_keys, key=len, reverse=True):
            ph = self._get_or_create("USER", u)
            cleaned = re.sub(rf"\b{re.escape(u)}\b", ph, cleaned)

        # Truncate evidence to ~600 chars
        return truncate_evidence(cleaned, max_chars=max_chars)

    def restore(self, text: str) -> str:
        """Restore placeholders back to original values using longest-placeholder-first.
        
        Invented placeholders (not in mapping) are left as-is and counted in stats.
        """
        if not text:
            return text

        # Check for invented placeholders not in our mapping
        all_placeholders = PLACEHOLDER_RE.findall(text)
        for ph in all_placeholders:
            if ph not in self.placeholder_to_val:
                self.unknown_placeholders += 1

        if not self.placeholder_to_val:
            return text

        # Sort placeholders by length descending so IP_10 is replaced before IP_1
        keys = sorted(self.placeholder_to_val.keys(), key=len, reverse=True)
        pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b")

        def _rep(m: re.Match[str]) -> str:
            return self.placeholder_to_val.get(m.group(1), m.group(1))

        return pattern.sub(_rep, text)

    def get_mapping(self) -> dict[str, str]:
        """Return a copy of the placeholder -> original value mapping."""
        return dict(self.placeholder_to_val)


def extract_known_entities(
    findings: list[Finding],
    host: str | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Extract known hostnames, usernames, and IPs from collector output / Finding fields."""
    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()

    if host and host != "unknown-host":
        hosts.add(host)

    for f in findings:
        if f.host and f.host != "unknown-host":
            hosts.add(f.host)

        # Extract IPs from target and evidence
        for ip in IPV4_RE.findall(f.target) + IPV4_RE.findall(f.evidence):
            ips.add(ip)

        # Extract potential usernames from target
        parts = f.target.split(":")
        if len(parts) >= 2 and parts[0] in ("sudoers", "user"):
            users.add(parts[1])
        elif f.domain in ("ssh", "privesc") and len(parts) >= 2:
            candidate = parts[1]
            if candidate and not candidate.startswith("Permit"):
                users.add(candidate)

    return list(hosts), list(users), list(ips)


def redact_text(
    text: str,
    redactor: Redactor | None = None,
    max_chars: int = 600,
) -> tuple[str, dict[str, str]]:
    """Convenience helper to redact text and return redacted string + mapping."""
    r = redactor or Redactor()
    redacted = r.redact(text, max_chars=max_chars)
    return redacted, r.get_mapping()


def restore_text(text: str, mapping: dict[str, str]) -> str:
    """Convenience helper to restore placeholders in text given a mapping using longest-first."""
    if not mapping or not text:
        return text
    keys = sorted(mapping.keys(), key=len, reverse=True)
    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b")
    return pattern.sub(lambda m: mapping.get(m.group(1), m.group(1)), text)
