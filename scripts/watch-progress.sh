#!/usr/bin/env bash

# 优先进入正在运行的 tmux 会话；若没有会话，则追踪最新日志。

set -euo pipefail

SESSION_NAME="${COTE3_TMUX_SESSION:-cote3mon}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${COTE3_LOG_DIR:-${PROJECT_ROOT}/artifacts/logs}"

if command -v tmux >/dev/null 2>&1 && tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
    cat <<EOF
即将进入 tmux 会话 ${SESSION_NAME}，你会实时看到任务输出。

安全离开但不停止任务：先按 Ctrl+B，松开后再按 D。
注意：不要用 Ctrl+C 离开；Ctrl+C 可能会中止正在运行的实验。
EOF
    exec tmux attach-session -t "$SESSION_NAME"
fi

if [[ ! -d "$LOG_DIR" ]]; then
    echo "目前还没有日志目录：${LOG_DIR}"
    echo "请先用 bash scripts/run-observable.sh 启动一个任务。"
    exit 1
fi

LATEST_LOG="$(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' \
    | sort -nr | head -n 1 | cut -d' ' -f2-)"

if [[ -z "$LATEST_LOG" ]]; then
    echo "目前还没有可查看的日志。"
    echo "请先用 bash scripts/run-observable.sh 启动一个任务。"
    exit 1
fi

cat <<EOF
没有发现正在运行的 ${SESSION_NAME} 会话，改为显示最新日志：
${LATEST_LOG}

这里按 Ctrl+C 只会停止查看日志，不会删除日志文件。
EOF

exec tail -n 80 -F "$LATEST_LOG"

