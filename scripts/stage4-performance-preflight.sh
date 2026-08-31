#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${COTE3_STAGE4_PYTHON:-${HOME}/.venvs/cote3-mon-stage3/bin/python}
BUILD=/tmp/cote3-host-perf
TEMP=$(mktemp -d)
cleanup() {
    rm -rf "$TEMP" "$BUILD"
}
trap cleanup EXIT INT TERM

cd "$PROJECT_ROOT"
bash -n scripts/stage4-qemu-session.sh scripts/stage4-performance-session.sh \
    scripts/stage4-performance-monitor.sh scripts/stage4-performance-host.sh
rm -rf "$BUILD"
make BUILD_DIR="$BUILD" all
COTE3_HOST_BUILD="$BUILD" bash tests/run_c_integration.sh
"$PYTHON" -m unittest discover -s tests -v

cp artifacts/stage4/20260719-formal-detection/raw/malformed-00-requests.jsonl \
    "$TEMP/requests.jsonl"
cp artifacts/stage4/20260719-formal-detection/raw/malformed-00-resources.jsonl \
    "$TEMP/resources.jsonl"
PYTHONPATH="$PROJECT_ROOT" "$PYTHON" scripts/guest-online-monitor.py \
    --requests "$TEMP/requests.jsonl" \
    --resources "$TEMP/resources.jsonl" \
    --model artifacts/stage4/20260719-formal-detection/models/iforest.json \
    --done-file "$TEMP/done" \
    --output "$TEMP/summary.json" \
    --alerts "$TEMP/alerts.jsonl" \
    --window-seconds 5 \
    --warmup-seconds 10 &
monitor_pid=$!
sleep 1
touch "$TEMP/done"
wait "$monitor_pid"
"$PYTHON" - "$TEMP/summary.json" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
assert summary["status"] == "PASS", summary
assert summary["windows"] > 0, summary
assert summary["alerts"] > 0, summary
print(json.dumps(summary, sort_keys=True))
PY

echo "COTE3_STAGE4_PERFORMANCE_PREFLIGHT_PASS"
