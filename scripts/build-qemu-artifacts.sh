#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OPTEE_ROOT" >&2
    exit 2
fi

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPTEE_ROOT=$(CDPATH= cd -- "$1" && pwd)
OUTPUT=${COTE3_QEMU_ARTIFACTS:-"$PROJECT_ROOT/artifacts/qemu-v8"}
AARCH64_BUILD_DIR="$PROJECT_ROOT/build/aarch64"
PATH="$OPTEE_ROOT/toolchains/rust/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
TEEC_EXPORT="$OPTEE_ROOT/out-br/staging/usr"
TA_DEV_KIT="$OPTEE_ROOT/optee_os/out/arm/export-ta_arm64"

CC=$(find "$OPTEE_ROOT/out-br/host/bin" -maxdepth 1 -name 'aarch64*gcc' | head -n 1)
test -n "$CC" || { echo "Buildroot AArch64 compiler not found; build OP-TEE first" >&2; exit 2; }
CROSS_COMPILE=${CC%gcc}
test -d "$TEEC_EXPORT/include" || { echo "TEEC export not found: $TEEC_EXPORT" >&2; exit 2; }
test -d "$TA_DEV_KIT" || { echo "TA dev kit not found: $TA_DEV_KIT" >&2; exit 2; }

make -C "$PROJECT_ROOT" BUILD_DIR="$AARCH64_BUILD_DIR" clean
make -C "$PROJECT_ROOT" -j"${JOBS:-4}" \
    BUILD_DIR="$AARCH64_BUILD_DIR" CC="$CC" all
make -C "$PROJECT_ROOT" BUILD_DIR="$AARCH64_BUILD_DIR" \
    CC="$CC" TEEC_EXPORT="$TEEC_EXPORT" optee-gateway
make -C "$PROJECT_ROOT/optee/audit_ta/ta" \
    TA_DEV_KIT_DIR="$TA_DEV_KIT" CROSS_COMPILE="$CROSS_COMPILE"
make -C "$PROJECT_ROOT/optee/audit_ta/host" \
    CC="$CC" TEEC_EXPORT="$TEEC_EXPORT"

mkdir -p "$OUTPUT"
cp "$AARCH64_BUILD_DIR/cote3-client" "$OUTPUT/"
cp "$AARCH64_BUILD_DIR/cote3-workload" "$OUTPUT/"
cp "$AARCH64_BUILD_DIR/cote3-gateway-optee" "$OUTPUT/"
cp "$PROJECT_ROOT/optee/audit_ta/host/audit-client" "$OUTPUT/"
cp "$PROJECT_ROOT/optee/audit_ta/ta/d4f052d5-8fd3-4cb8-a497-3f6a0cb88710.ta" "$OUTPUT/"

echo "QEMU AArch64 artifacts written to $OUTPUT"
