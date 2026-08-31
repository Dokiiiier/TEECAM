#!/usr/bin/env sh
set -eu

OPTEE_VERSION="4.10.0"
OPTEE_ROOT="${1:-$HOME/cote3-optee-qemu-v8}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

for command in git make python3 repo; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing required command: $command" >&2
        exit 2
    }
done

mkdir -p "$OPTEE_ROOT"
cd "$OPTEE_ROOT"
if [ ! -d .repo ]; then
    repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b "$OPTEE_VERSION"
fi
repo sync -j"$JOBS" --no-clone-bundle
make -C build -j"$JOBS" toolchains

cat <<EOF
OP-TEE $OPTEE_VERSION source and toolchains are ready in $OPTEE_ROOT.
Run: make -C "$OPTEE_ROOT/build" -j"$JOBS" run
At the Buildroot prompt, run: xtest
EOF
