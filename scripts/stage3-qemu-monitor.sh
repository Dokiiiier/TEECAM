#!/usr/bin/env bash
set -euo pipefail

ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE3_RUN_TAG:-20260718-ai-smoke}
LOG="$ROOT/cote3-stage3/logs/normal-world.log"
RAW="$ROOT/cote3-stage3/$RUN_TAG/raw"

for tick in $(seq 1 80); do
    completed=$(find "$RAW" -maxdepth 1 -type f -name '*-result.json' 2>/dev/null | wc -l)
    latest=$(grep -E '^(running|completed|COTE3_STAGE3_QEMU_COLLECTION_PASS|Traceback|RuntimeError|TimeoutError)' "$LOG" \
        | tail -n 1 || true)
    printf 'stage3_progress=%s/21 elapsed_approx=%ss latest=%s\n' \
        "$completed" "$((tick * 15))" "${latest:-staging OCI rootfs}"
    if grep -q '^COTE3_STAGE3_QEMU_COLLECTION_PASS' "$LOG"; then
        [ "$completed" -eq 21 ] || { echo "success marker found but result count is $completed" >&2; exit 1; }
        echo "COTE3_STAGE3_QEMU_COLLECTION_MONITORED_PASS"
        exit 0
    fi
    if grep -qE '^(Traceback|RuntimeError|TimeoutError)' "$LOG"; then
        echo "COTE3_STAGE3_QEMU_COLLECTION_FAILED"
        tail -n 35 "$LOG"
        exit 1
    fi
    sleep 15
done

echo "COTE3_STAGE3_QEMU_COLLECTION_TIMEOUT" >&2
tail -n 35 "$LOG"
exit 1
