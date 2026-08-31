#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
VENV=${COTE3_STAGE4_VENV:-${HOME}/.venvs/cote3-mon-stage3}
SOURCE_RAW="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/raw"
OUTPUT="$PROJECT_ROOT/artifacts/stage4/$RUN_TAG"
GUEST_ANALYSIS="$OPTEE_ROOT/cote3-stage4/$RUN_TAG/analysis"

test -x "$VENV/bin/python" || { echo "training virtual environment is missing" >&2; exit 1; }
test -d "$SOURCE_RAW" || { echo "QEMU raw data is missing: $SOURCE_RAW" >&2; exit 1; }
test ! -e "$OUTPUT" || { echo "refusing to overwrite existing formal evidence: $OUTPUT" >&2; exit 1; }
test ! -e "$GUEST_ANALYSIS" || { echo "refusing to overwrite existing guest analysis: $GUEST_ANALYSIS" >&2; exit 1; }

mkdir -p "$OUTPUT"
cp -a "$SOURCE_RAW" "$OUTPUT/raw"
"$VENV/bin/python" -m pip freeze >"$OUTPUT/python-environment-freeze.txt"
"$VENV/bin/python" "$PROJECT_ROOT/scripts/stage3-train-evaluate.py" \
    --raw "$OUTPUT/raw" \
    --config "$PROJECT_ROOT/experiments/stage4-formal.json" \
    --output "$OUTPUT" \
    --bootstrap-iterations 5000 \
    | tee "$OUTPUT/host-pipeline.log"

mkdir -p "$(dirname "$GUEST_ANALYSIS")"
cp -a "$OUTPUT" "$GUEST_ANALYSIS"
echo "COTE3_STAGE4_HOST_ARTIFACTS_READY"
echo "output=$OUTPUT"
echo "guest_analysis=$GUEST_ANALYSIS"
