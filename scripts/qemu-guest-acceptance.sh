#!/usr/bin/env sh
set -eu

BUNDLE=${1:-/mnt/host/cote3-bundle}
OUTPUT=${2:-/mnt/host/cote3-stage2-results}
INSTALL_ROOT=${COTE3_INSTALL_ROOT:-/opt/cote3-mon}
AUDIT_CLIENT=${COTE3_AUDIT_CLIENT:-/usr/bin/audit-client}
SOCKET=/run/cote3-mon/gateway.sock
GATEWAY_PID=
CONTAINER_ID=cote3-stage2
TEMP_BUNDLE=/tmp/cote3-stage2-bundle

cleanup() {
    runc delete --force "$CONTAINER_ID" >/dev/null 2>&1 || true
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" >/dev/null 2>&1 || true
        wait "$GATEWAY_PID" >/dev/null 2>&1 || true
    fi
    umount "$TEMP_BUNDLE/rootfs" >/dev/null 2>&1 || true
    rm -rf "$TEMP_BUNDLE"
    rm -f "$SOCKET"
}
trap cleanup EXIT INT TERM

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

if ! mount | grep -q ' on /mnt/host '; then
    mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/host
fi

mkdir -p "$OUTPUT" /run/cote3-mon
rm -rf "$TEMP_BUNDLE"
mkdir -p "$TEMP_BUNDLE/rootfs"
rm -f "$OUTPUT/request-events.jsonl" "$OUTPUT/gateway.log" \
    "$OUTPUT/container.log" "$OUTPUT/protocol-client.log"

[ "$(uname -m)" = "aarch64" ] || fail "guest architecture is not aarch64"
[ -c /dev/tee0 ] || fail "host CA device /dev/tee0 is missing"
[ -c /dev/teepriv0 ] || fail "tee-supplicant device /dev/teepriv0 is missing"
command -v runc >/dev/null 2>&1 || fail "runc is missing"
command -v python3 >/dev/null 2>&1 || fail "python3 is missing"
if ! mount | grep -q ' on /sys/fs/cgroup '; then
    mkdir -p /sys/fs/cgroup
    mount -t cgroup2 cgroup2 /sys/fs/cgroup \
        || fail "cgroup v2 could not be mounted"
fi
[ -d "$BUNDLE/rootfs" ] || fail "OCI bundle rootfs is missing: $BUNDLE"
[ -f "$BUNDLE/config.json" ] || fail "OCI config is missing: $BUNDLE"
[ ! -e "$BUNDLE/rootfs/dev/tee0" ] || fail "bundle contains /dev/tee0"
[ ! -e "$BUNDLE/rootfs/dev/teepriv0" ] || fail "bundle contains /dev/teepriv0"
pass "guest platform and bundle prerequisites"

cp -a "$BUNDLE/rootfs/." "$TEMP_BUNDLE/rootfs/"
mount --bind "$TEMP_BUNDLE/rootfs" "$TEMP_BUNDLE/rootfs" \
    || fail "guest-local OCI rootfs could not be bind-mounted"
pass "OCI rootfs staged on the guest-local tmpfs"

python3 - "$BUNDLE/config.json" "$TEMP_BUNDLE/rootfs" "$TEMP_BUNDLE/config.json" <<'PY'
import json
from pathlib import Path
import sys

source, rootfs, target = map(Path, sys.argv[1:])
config = json.loads(source.read_text(encoding="utf-8"))
config["root"]["path"] = str(rootfs)
config["process"]["args"] = [
    "/bin/sh",
    "-c",
    "test ! -e /dev/tee0 && test ! -e /dev/teepriv0 && "
    "echo TEE_DEVICES_BLOCKED && "
    "/bin/cote3-client put container-key container-secret && "
    "/bin/cote3-client get container-key && "
    "/bin/cote3-client delete container-key",
]
target.write_text(json.dumps(config, indent=2), encoding="utf-8")
PY

rm -f "$SOCKET"
COTE3_RUN_ID=stage2-container \
COTE3_CONTAINER_ID="$CONTAINER_ID" \
COTE3_SCENARIO=container-put-get-delete \
    /usr/bin/cote3-gateway-optee \
        --backend optee --socket "$SOCKET" \
        --telemetry "$OUTPUT/request-events.jsonl" \
        >"$OUTPUT/gateway.log" 2>&1 &
GATEWAY_PID=$!

attempt=0
while [ ! -S "$SOCKET" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -le 100 ] || fail "gateway socket did not appear"
    sleep 0.05
done

runc delete --force "$CONTAINER_ID" >/dev/null 2>&1 || true
runc run --no-pivot --bundle "$TEMP_BUNDLE" "$CONTAINER_ID" \
    >"$OUTPUT/container.log" 2>&1 \
    || fail "runc container execution failed"
runc delete --force "$CONTAINER_ID" >/dev/null 2>&1 || true

grep -q '^TEE_DEVICES_BLOCKED$' "$OUTPUT/container.log" \
    || fail "container could see a TEE device"
grep -q '^OK container-secret$' "$OUTPUT/container.log" \
    || fail "container GET did not return the stored value"
pass "container accesses secure storage only through the gateway"

python3 - "$SOCKET" >"$OUTPUT/protocol-client.log" <<'PY'
import socket
import struct
import sys

path = sys.argv[1]

def send(payload):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(path)
    client.sendall(payload)
    client.close()

magic = 0x43334D31
version = 1
send(struct.pack("!IHHQII", magic, version, 99, 1, 1, 0) + b"k")
send(struct.pack("!IHHQII", magic, version, 1, 2, 1, 4097) + b"k")
send(b"partial")
print("SENT_UNKNOWN_OVERSIZED_INCOMPLETE")
PY

sleep 1
kill "$GATEWAY_PID" >/dev/null 2>&1 || true
wait "$GATEWAY_PID" >/dev/null 2>&1 || true
GATEWAY_PID=

python3 - "$OUTPUT/request-events.jsonl" <<'PY'
import json
from pathlib import Path
import sys

events = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
operations = [event["operation"] for event in events]
assert operations[:3] == ["PUT", "GET", "DELETE"], operations
rejects = [event for event in events if event["operation"] == "REJECT"]
assert len(rejects) == 3, rejects
assert all(event["result"] == "PROTOCOL_ERROR" for event in rejects), rejects
print(f"VALIDATED_REQUEST_EVENTS={len(events)}")
print(f"VALIDATED_PROTOCOL_REJECTIONS={len(rejects)}")
PY
pass "gateway rejects unknown, oversized and incomplete requests"

PYTHONPATH="$INSTALL_ROOT" \
    python3 "$INSTALL_ROOT/qemu-audit-acceptance.py" \
        --audit-client "$AUDIT_CLIENT" --output "$OUTPUT"
pass "audit TA detects receipt-chain tampering"

cat >"$OUTPUT/summary.json" <<EOF
{
  "schema": "cote3-mon-stage2-acceptance-v1",
  "status": "PASS",
  "checks": [
    "aarch64 guest and TEE devices",
    "container TEE-device isolation",
    "container gateway PUT/GET/DELETE",
    "protocol rejection telemetry",
    "audit TA receipt verification",
    "audit modification deletion reordering forgery rejection"
  ]
}
EOF

echo "COTE3_STAGE2_ACCEPTANCE_PASS"
