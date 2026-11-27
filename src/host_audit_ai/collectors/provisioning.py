"""Core-only SSH target provisioning helpers for forced-command inspection."""

from __future__ import annotations

import hashlib
import importlib.resources
import ipaddress
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_WRAPPER_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@-]{1,256}$")
_COMMENT_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")


class ProvisioningError(Exception):
    """Raised when SSH key generation or authorized_keys provisioning fails."""


@dataclass(frozen=True)
class KeypairResult:
    """Metadata for a generated ed25519 audit SSH keypair (never stores private key material)."""

    private_key_path: Path
    public_key_path: Path
    public_key: str
    fingerprint: str


@dataclass(frozen=True)
class TargetSetupBundle:
    """Complete target provisioning bundle for hardened read-only SSH access."""

    keypair: KeypairResult
    wrapper_path: str
    wrapper_sha256: str
    wrapper_script: str
    authorized_keys_entry: str
    instructions: str


def load_wrapper_script_text() -> str:
    """Load bundled host-audit-wrapper.sh text via importlib.resources."""
    ref = importlib.resources.files("host_audit_ai.collectors.scripts").joinpath(
        "host-audit-wrapper.sh"
    )
    return ref.read_text(encoding="utf-8")


def validate_wrapper_path(wrapper_path: str) -> str:
    """Validate target-side wrapper binary path."""
    cleaned = wrapper_path.strip()
    if not _WRAPPER_PATH_RE.fullmatch(cleaned) or ".." in cleaned:
        raise ValueError(
            f"Invalid wrapper path '{wrapper_path}': must be a clean absolute path without '..'"
        )
    return cleaned


def generate_audit_keypair(
    key_path: Path,
    comment: str = "host-audit-ai",
    force: bool = False,
) -> KeypairResult:
    """Generate a dedicated ed25519 SSH keypair using ssh-keygen with strict file permissions."""
    if not _COMMENT_RE.fullmatch(comment):
        raise ValueError(f"Invalid key comment '{comment}'")

    resolved_key = key_path.expanduser()
    pub_path = resolved_key.with_name(f"{resolved_key.name}.pub")

    if (resolved_key.exists() or pub_path.exists()) and not force:
        raise FileExistsError(
            f"Keypair already exists at '{resolved_key}' (pass --force to overwrite)."
        )

    parent_existed = resolved_key.parent.exists()
    resolved_key.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix" and (not parent_existed or resolved_key.parent.name == ".ssh"):
        os.chmod(resolved_key.parent, 0o700)

    if force:
        if resolved_key.exists():
            resolved_key.unlink()
        if pub_path.exists():
            pub_path.unlink()

    keygen_bin = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
    try:
        proc = subprocess.run(  # noqa: S603
            [
                keygen_bin,
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                comment,
                "-f",
                str(resolved_key),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as e:
        raise ProvisioningError(f"Failed to execute ssh-keygen: {e}") from e

    if proc.returncode != 0:
        err_text = proc.stderr.strip() or proc.stdout.strip()
        raise ProvisioningError(f"ssh-keygen failed (exit {proc.returncode}): {err_text}")

    if os.name == "posix":
        os.chmod(resolved_key, 0o600)
        if pub_path.exists():
            os.chmod(pub_path, 0o644)

    public_key = pub_path.read_text(encoding="utf-8").strip()

    # Read OpenSSH SHA256 fingerprint without exposing private key
    fp_proc = subprocess.run(  # noqa: S603
        [keygen_bin, "-lf", str(pub_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    fingerprint = (
        fp_proc.stdout.strip().split()[1]
        if fp_proc.returncode == 0 and len(fp_proc.stdout.strip().split()) >= 2
        else hashlib.sha256(public_key.encode("utf-8")).hexdigest()
    )

    return KeypairResult(
        private_key_path=resolved_key,
        public_key_path=pub_path,
        public_key=public_key,
        fingerprint=fingerprint,
    )


def build_authorized_keys_entry(
    public_key: str,
    wrapper_path: str = "/usr/local/bin/host-audit-wrapper",
    from_cidr: str | None = None,
) -> str:
    """Construct a forced-command, restricted authorized_keys line."""
    clean_wrapper = validate_wrapper_path(wrapper_path)
    clean_pubkey = " ".join(public_key.strip().splitlines()).strip()
    if not clean_pubkey or not clean_pubkey.startswith("ssh-"):
        raise ValueError("Invalid SSH public key string.")

    options = [f'command="{clean_wrapper}"', "restrict"]
    if from_cidr is not None and from_cidr.strip():
        net = ipaddress.ip_network(from_cidr.strip(), strict=False)
        options.append(f'from="{net}"')

    return f"{','.join(options)} {clean_pubkey}"


def render_target_setup_bundle(
    key_path: Path,
    wrapper_path: str = "/usr/local/bin/host-audit-wrapper",
    from_cidr: str | None = None,
    comment: str = "host-audit-ai",
    force: bool = False,
) -> TargetSetupBundle:
    """Generate audit keypair, wrapper script text, authorized_keys entry, and setup guide."""
    clean_wrapper = validate_wrapper_path(wrapper_path)
    keypair = generate_audit_keypair(key_path=key_path, comment=comment, force=force)
    wrapper_script = load_wrapper_script_text()
    wrapper_sha256 = hashlib.sha256(wrapper_script.encode("utf-8")).hexdigest()
    auth_entry = build_authorized_keys_entry(
        keypair.public_key,
        wrapper_path=clean_wrapper,
        from_cidr=from_cidr,
    )

    instructions = "\n".join(
        [
            "Target Provisioning Steps (execute on target host as root):",
            f"1. Install wrapper script to {clean_wrapper}:",
            f"   install -m 0755 -o root -g root host-audit-wrapper.sh {clean_wrapper}",
            f"   sha256sum {clean_wrapper}  # expected: {wrapper_sha256}",
            "2. Append the forced-command entry to the audit user's ~/.ssh/authorized_keys:",
            f"   {auth_entry}",
            "3. Verify read-only connectivity from your workstation:",
            f"   ssh -i {keypair.private_key_path} <user>@<target> ping",
        ]
    )

    return TargetSetupBundle(
        keypair=keypair,
        wrapper_path=clean_wrapper,
        wrapper_sha256=wrapper_sha256,
        wrapper_script=wrapper_script,
        authorized_keys_entry=auth_entry,
        instructions=instructions,
    )
