#!/usr/bin/env bash
set -euo pipefail

ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
LOG="$ROOT/cote3-stage4/$RUN_TAG/performance-formal/logs/normal-world.log"
RAW="$ROOT/cote3-stage4/$RUN_TAG/performance/raw"
EXPECTED=40

for tick in $(seq 1 240); do
    completed=$(find "$RAW" -maxdepth 1 -type f -name '*-result.json' 2>/dev/null | wc -l)
    latest=$(grep -E '^(running|completed|skipping|COTE3_STAGE4_PERFORMANCE_QEMU_PASS|Traceback|RuntimeError|TimeoutError)' "$LOG" \
        | tail -n 1 || true)
    printf 'stage4_performance_progress=%s/%s monitor_tick=%s latest=%s\n' \
        "$completed" "$EXPECTED" "$tick" "${latest:-staging OCI rootfs}"
    if grep -q '^COTE3_STAGE4_PERFORMANCE_QEMU_PASS' "$LOG"; then
        [ "$completed" -eq "$EXPECTED" ] || { echo "success marker found but result count is $completed" >&2; exit 1; }
        echo "COTE3_STAGE4_PERFORMANCE_MONITORED_PASS"
        exit 0
    fi
    if grep -qE '^(Traceback|RuntimeError|TimeoutError)' "$LOG"; then
        echo "COTE3_STAGE4_PERFORMANCE_FAILED"
        tail -n 35 "$LOG"
        exit 1
    fi
    if ! pgrep -f '[/]qemu-system-aarch64' >/dev/null 2>&1; then
        echo "COTE3_STAGE4_PERFORMANCE_QEMU_MISSING" >&2
        tail -n 35 "$LOG"
        exit 1
    fi
    sleep 15
done

echo "COTE3_STAGE4_PERFORMANCE_TIMEOUT" >&2
tail -n 35 "$LOG"
exit 1
