#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
VENV=${COTE3_STAGE4_VENV:-${HOME}/.venvs/cote3-mon-stage3}
SOURCE="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/performance"
LOG_SOURCE="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/performance-formal/logs"
OUTPUT="$PROJECT_ROOT/artifacts/stage4/$RUN_TAG/performance"

test -d "$SOURCE/raw" || { echo "performance raw evidence is missing" >&2; exit 1; }
test -d "$LOG_SOURCE" || { echo "performance QEMU logs are missing" >&2; exit 1; }
test ! -e "$OUTPUT" || { echo "refusing to overwrite formal performance evidence" >&2; exit 1; }

mkdir -p "$OUTPUT"
cp -a "$SOURCE/raw" "$OUTPUT/raw"
cp -a "$LOG_SOURCE" "$OUTPUT/qemu-logs"
"$VENV/bin/python" "$PROJECT_ROOT/scripts/stage4-analyze-performance.py" \
    --raw "$OUTPUT/raw" \
    --config "$PROJECT_ROOT/experiments/stage4-performance.json" \
    --output "$OUTPUT" \
    --bootstrap-iterations 5000 \
    | tee "$OUTPUT/analysis.log"

echo "COTE3_STAGE4_PERFORMANCE_EVIDENCE_READY"
echo "output=$OUTPUT"
