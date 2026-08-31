#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 ROOTFS_DIRECTORY COTE3_CLIENT_BINARY COTE3_WORKLOAD_BINARY" >&2
    exit 2
fi

ROOTFS=$1
CLIENT=$2
WORKLOAD=$3
BUNDLE="${BUNDLE:-$(pwd)/artifacts/oci/cote3-workload}"

test -d "$ROOTFS" || { echo "rootfs directory not found" >&2; exit 2; }
test -x "$CLIENT" || { echo "client binary not found or not executable" >&2; exit 2; }
test -x "$WORKLOAD" || { echo "workload binary not found or not executable" >&2; exit 2; }

if [ -d "$BUNDLE/rootfs" ]; then
    # Files copied from Buildroot include read-only TAs.  Make only the old
    # bundle copy writable so a repeatable refresh can replace those files.
    chmod -R u+w "$BUNDLE/rootfs"
fi
mkdir -p "$BUNDLE/rootfs/bin"
cp -a "$ROOTFS/." "$BUNDLE/rootfs/"
install -m 0755 "$CLIENT" "$BUNDLE/rootfs/bin/cote3-client"
install -m 0755 "$WORKLOAD" "$BUNDLE/rootfs/bin/cote3-workload"
cp container/config.json "$BUNDLE/config.json"

echo "OCI bundle ready at $BUNDLE"
echo "Security check: test ! -e '$BUNDLE/rootfs/dev/tee0' && test ! -e '$BUNDLE/rootfs/dev/teepriv0'"
