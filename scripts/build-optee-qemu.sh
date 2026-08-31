#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OPTEE_ROOT" >&2
    exit 2
fi

OPTEE_ROOT=$(CDPATH= cd -- "$1" && pwd)
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
PATH="$OPTEE_ROOT/toolchains/rust/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

# OP-TEE's build makefile writes BR2_* command-line variables into out-br/extra.conf.
make -C "$OPTEE_ROOT/build" -j"$JOBS" \
    BR2_PACKAGE_PYTHON3=y \
    BR2_PACKAGE_RUNC=y \
    BR2_PACKAGE_LIBSECCOMP=y \
    all
