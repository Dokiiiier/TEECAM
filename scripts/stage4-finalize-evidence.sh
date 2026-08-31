#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
VENV=${COTE3_STAGE4_VENV:-${HOME}/.venvs/cote3-mon-stage3}
OUTPUT="$PROJECT_ROOT/artifacts/stage4/$RUN_TAG"
GUEST_ANALYSIS="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/analysis"
LOG_SOURCE="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/logs"

test -d "$OUTPUT" || { echo "host evidence is missing: $OUTPUT" >&2; exit 1; }
test -f "$GUEST_ANALYSIS/parity-guest.json" || { echo "guest parity evidence is missing" >&2; exit 1; }
test ! -e "$OUTPUT/parity-guest.json" || { echo "refusing to overwrite guest parity evidence" >&2; exit 1; }
test ! -e "$OUTPUT/qemu-logs" || { echo "refusing to overwrite QEMU logs" >&2; exit 1; }

cp "$GUEST_ANALYSIS/parity-guest.json" "$OUTPUT/parity-guest.json"
cp -a "$LOG_SOURCE" "$OUTPUT/qemu-logs"
"$VENV/bin/python" "$PROJECT_ROOT/scripts/stage3-finalize.py" --output "$OUTPUT" \
    | tee "$OUTPUT/finalize.log"

echo "COTE3_STAGE4_EVIDENCE_ARCHIVED"
echo "output=$OUTPUT"
