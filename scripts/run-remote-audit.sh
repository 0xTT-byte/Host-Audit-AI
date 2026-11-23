#!/usr/bin/env bash
# scripts/run-remote-audit.sh - Stream audit collector over SSH and analyze locally
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COLLECT_SCRIPT="$REPO_ROOT/collect/audit-collect.sh"

usage() {
    echo "Usage: $0 <user@host> [baseline.yml] [--no-llm] [extra host-audit args...]"
    echo "Example: $0 admin@192.168.1.50 baselines/docker-host.yml --no-llm"
    exit 1
}

if [ "$#" -lt 1 ]; then
    usage
fi

TARGET="$1"
shift

BASELINE="$REPO_ROOT/baselines/docker-host.yml"
EXTRA_ARGS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-llm)
            EXTRA_ARGS+=("--no-llm")
            shift
            ;;
        --baseline)
            BASELINE="$2"
            shift 2
            ;;
        *.yml|*.yaml)
            BASELINE="$1"
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ! -f "$COLLECT_SCRIPT" ]; then
    echo "Error: Collector script not found at $COLLECT_SCRIPT" >&2
    exit 1
fi

if [ ! -f "$BASELINE" ]; then
    echo "Error: Baseline YAML not found at $BASELINE" >&2
    exit 1
fi

# Sanitize hostname for directory naming
HOST_LABEL=$(echo "$TARGET" | tr '@:' '_')
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="$REPO_ROOT/evidence/${HOST_LABEL}-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "[*] Connecting to $TARGET..."
echo "[*] Executing read-only collector remotely (streaming archive back, 0 files left behind)..."

# Stream the collector script over SSH, run in temp directory, tar stdout back, and wipe remote directory on EXIT trap
ssh -T "$TARGET" "bash -c '
    set -euo pipefail
    REMOTE_TMP=\$(mktemp -d /tmp/audit-host.XXXXXX)
    chmod 700 \"\$REMOTE_TMP\"
    trap \"rm -rf \\\"\$REMOTE_TMP\\\"\" EXIT
    AUDIT_OUT=\"\$REMOTE_TMP\" bash -s >/dev/null
    tar -C \"\$REMOTE_TMP\" -cf - .
'" < "$COLLECT_SCRIPT" | tar -C "$EVIDENCE_DIR" -xf -

echo "[*] Evidence collected successfully in: $EVIDENCE_DIR"
echo "[*] Running host-audit analyzer..."

if command -v host-audit >/dev/null 2>&1; then
    host-audit analyze \
        --collect-dir "$EVIDENCE_DIR" \
        --baseline "$BASELINE" \
        --out-dir "$EVIDENCE_DIR" \
        ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
elif [ -f "$REPO_ROOT/.venv/bin/host-audit" ]; then
    "$REPO_ROOT/.venv/bin/host-audit" analyze \
        --collect-dir "$EVIDENCE_DIR" \
        --baseline "$BASELINE" \
        --out-dir "$EVIDENCE_DIR" \
        ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
else
    python3 -m host_audit.cli analyze \
        --collect-dir "$EVIDENCE_DIR" \
        --baseline "$BASELINE" \
        --out-dir "$EVIDENCE_DIR" \
        ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
fi

echo "[*] Audit complete. Artifacts written to: $EVIDENCE_DIR"
