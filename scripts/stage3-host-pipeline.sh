#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE3_RUN_TAG:-20260718-ai-smoke}
VENV=${COTE3_STAGE3_VENV:-${HOME}/.venvs/cote3-mon-stage3}
SOURCE_RAW="$OPTEE_ROOT/cote3-stage3/$RUN_TAG/raw"
OUTPUT="$PROJECT_ROOT/artifacts/stage3/$RUN_TAG"

test -x "$VENV/bin/python" || { echo "training virtual environment is missing" >&2; exit 1; }
test -d "$SOURCE_RAW" || { echo "QEMU raw data is missing: $SOURCE_RAW" >&2; exit 1; }
test ! -e "$OUTPUT/raw" || { echo "refusing to overwrite existing raw evidence: $OUTPUT/raw" >&2; exit 1; }

mkdir -p "$OUTPUT"
cp -a "$SOURCE_RAW" "$OUTPUT/raw"
"$VENV/bin/python" -m pip freeze >"$OUTPUT/python-environment-freeze.txt"
"$VENV/bin/python" "$PROJECT_ROOT/scripts/stage3-train-evaluate.py" \
    --raw "$OUTPUT/raw" \
    --config "$PROJECT_ROOT/experiments/stage3-smoke.json" \
    --output "$OUTPUT" \
    --bootstrap-iterations 1000 \
    | tee "$OUTPUT/host-pipeline.log"

echo "COTE3_STAGE3_HOST_ARTIFACTS_READY"
echo "output=$OUTPUT"
