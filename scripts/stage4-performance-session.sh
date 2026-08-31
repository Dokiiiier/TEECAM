#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
export COTE3_STAGE4_SESSION=${COTE3_STAGE4_PERFORMANCE_SESSION:-cote3-stage4-performance}
export COTE3_STAGE4_LOG_ROOT="$ROOT/cote3-stage4/$RUN_TAG/performance-formal/logs"
exec "$SCRIPT_DIR/stage4-qemu-session.sh" "$@"
