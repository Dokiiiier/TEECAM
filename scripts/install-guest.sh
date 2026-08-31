#!/usr/bin/env sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 TARGET_ROOTFS GATEWAY CLIENT WORKLOAD AUDIT_CLIENT AUDIT_TA" >&2
    exit 2
fi

TARGET=$1
GATEWAY=$2
CLIENT=$3
WORKLOAD=$4
AUDIT_CLIENT=$5
AUDIT_TA=$6
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for file in "$GATEWAY" "$CLIENT" "$WORKLOAD" "$AUDIT_CLIENT" "$AUDIT_TA"; do
    test -f "$file" || { echo "missing artifact: $file" >&2; exit 2; }
done

install -d "$TARGET/usr/bin" "$TARGET/lib/optee_armtz" "$TARGET/opt/cote3-mon"
install -m 0755 "$GATEWAY" "$TARGET/usr/bin/cote3-gateway-optee"
install -m 0755 "$CLIENT" "$TARGET/usr/bin/cote3-client"
install -m 0755 "$WORKLOAD" "$TARGET/usr/bin/cote3-workload"
install -m 0755 "$AUDIT_CLIENT" "$TARGET/usr/bin/audit-client"
install -m 0444 "$AUDIT_TA" "$TARGET/lib/optee_armtz/d4f052d5-8fd3-4cb8-a497-3f6a0cb88710.ta"
cp -a "$PROJECT_ROOT/cote3mon" "$TARGET/opt/cote3-mon/"
cp -a "$PROJECT_ROOT/experiments" "$TARGET/opt/cote3-mon/"
cp -a "$PROJECT_ROOT/scripts/run-qemu-experiments.py" "$TARGET/opt/cote3-mon/"
install -m 0755 "$PROJECT_ROOT/scripts/stage5-feature-ablation.py" \
    "$TARGET/opt/cote3-mon/stage5-feature-ablation.py"
install -m 0755 "$PROJECT_ROOT/scripts/qemu-audit-acceptance.py" \
    "$TARGET/opt/cote3-mon/qemu-audit-acceptance.py"
install -m 0755 "$PROJECT_ROOT/scripts/qemu-guest-acceptance.sh" \
    "$TARGET/opt/cote3-mon/qemu-guest-acceptance.sh"
install -m 0755 "$PROJECT_ROOT/scripts/qemu-model-parity.py" \
    "$TARGET/opt/cote3-mon/qemu-model-parity.py"
install -m 0755 "$PROJECT_ROOT/scripts/guest-online-monitor.py" \
    "$TARGET/opt/cote3-mon/guest-online-monitor.py"
install -m 0755 "$PROJECT_ROOT/scripts/run-qemu-performance.py" \
    "$TARGET/opt/cote3-mon/run-qemu-performance.py"

echo "COTE3-Mon installed in guest rootfs: $TARGET"
