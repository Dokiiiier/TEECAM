#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OPTEE_ROOT" >&2
    exit 2
fi

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=$(CDPATH= cd -- "$1" && pwd)
ARTIFACTS=${COTE3_QEMU_ARTIFACTS:-"$PROJECT_ROOT/artifacts/qemu-v8"}
TARGET="$OPTEE_ROOT/out-br/target"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

"$PROJECT_ROOT/scripts/install-guest.sh" "$TARGET" \
    "$ARTIFACTS/cote3-gateway-optee" \
    "$ARTIFACTS/cote3-client" \
    "$ARTIFACTS/cote3-workload" \
    "$ARTIFACTS/audit-client" \
    "$ARTIFACTS/d4f052d5-8fd3-4cb8-a497-3f6a0cb88710.ta"

BUNDLE="$OPTEE_ROOT/cote3-bundle" \
    "$PROJECT_ROOT/scripts/prepare-oci-bundle.sh" "$TARGET" \
    "$ARTIFACTS/cote3-client" "$ARTIFACTS/cote3-workload"

# Rebuild only the root filesystem image after injecting the fixed artifacts.
make -C "$OPTEE_ROOT/out-br"

echo "Rootfs rebuilt. Start QEMU with:"
echo "OCI bundle: $OPTEE_ROOT/cote3-bundle"
echo "make -C '$OPTEE_ROOT/build' QEMU_VIRTFS_ENABLE=y QEMU_VIRTFS_AUTOMOUNT=y QEMU_VIRTFS_HOST_DIR='$OPTEE_ROOT' run-only"
