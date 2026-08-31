#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOST_BUILD=${COTE3_HOST_BUILD:-$PROJECT_ROOT/build/host}
TEMP_DIR=$(mktemp -d)
SOCKET="$TEMP_DIR/gateway.sock"
TELEMETRY="$TEMP_DIR/telemetry.jsonl"
SUMMARY="$TEMP_DIR/summary.json"
GATEWAY_PID=

cleanup() {
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT INT TERM

COTE3_RUN_ID=c-integration \
COTE3_CONTAINER_ID=test-container \
COTE3_SCENARIO=steady \
    "$HOST_BUILD/cote3-gateway" \
        --socket "$SOCKET" --telemetry "$TELEMETRY" --summary "$SUMMARY" --backend mock &
GATEWAY_PID=$!

attempt=0
while [ ! -S "$SOCKET" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 100 ]; then
        echo "gateway socket did not appear" >&2
        exit 1
    fi
    sleep 0.02
done

test "$("$HOST_BUILD/cote3-client" --socket "$SOCKET" put alpha secret)" = "OK"
test "$("$HOST_BUILD/cote3-client" --socket "$SOCKET" get alpha)" = "OK secret"
test "$("$HOST_BUILD/cote3-client" --socket "$SOCKET" delete alpha)" = "OK"
"$HOST_BUILD/cote3-workload" malformed --socket "$SOCKET" --duration 0.05 --seed 42

kill "$GATEWAY_PID"
wait "$GATEWAY_PID" || true
GATEWAY_PID=

python3 - "$TELEMETRY" "$SUMMARY" <<'PY'
import json
import sys

events = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
summary = json.load(open(sys.argv[2], encoding="utf-8"))
assert len(events) >= 4, events
assert [event["operation"] for event in events[:3]] == ["PUT", "GET", "DELETE"]
assert any(event["operation"] == "REJECT" for event in events)
assert all(event["run_id"] == "c-integration" for event in events)
assert all("key_fingerprint" in event for event in events)
assert all("request_fingerprint" in event for event in events)
assert all("key" not in event and "value" not in event for event in events)
assert events[0]["key_fingerprint"] == events[1]["key_fingerprint"]
assert events[0]["request_fingerprint"] != events[1]["request_fingerprint"]
assert summary["schema"] == "cote3-mon-gateway-summary-v1"
assert summary["requests"] == len(events)
assert summary["latency_p50_us"] >= 0
print(f"validated {len(events)} C gateway telemetry events")
PY
