"""Host Audit AI collector subsystem."""

from host_audit_ai.collectors.framing import CollectorFramingError, decode_envelope
from host_audit_ai.collectors.provisioning import (
    KeypairResult,
    ProvisioningError,
    TargetSetupBundle,
    build_authorized_keys_entry,
    generate_audit_keypair,
    load_wrapper_script_text,
    render_target_setup_bundle,
    validate_wrapper_path,
)
from host_audit_ai.collectors.transport import (
    CollectorTransport,
    CollectorTransportError,
    LocalTransport,
    OfflineTransport,
    SSHTarget,
    SSHTransport,
    get_collector_script_bytes,
    save_capture,
)

__all__ = [
    "CollectorFramingError",
    "CollectorTransport",
    "CollectorTransportError",
    "KeypairResult",
    "LocalTransport",
    "OfflineTransport",
    "ProvisioningError",
    "SSHTransport",
    "SSHTarget",
    "TargetSetupBundle",
    "build_authorized_keys_entry",
    "decode_envelope",
    "generate_audit_keypair",
    "get_collector_script_bytes",
    "load_wrapper_script_text",
    "render_target_setup_bundle",
    "save_capture",
    "validate_wrapper_path",
]
