#!/usr/bin/env bash

# 汇总 tmux、QEMU 和最近日志状态，不会启动或停止任何任务。

set -euo pipefail

SESSION_NAME="${COTE3_TMUX_SESSION:-cote3mon}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${COTE3_LOG_DIR:-${PROJECT_ROOT}/artifacts/logs}"

echo "========== COTE3-Mon 当前状态 =========="
echo "项目目录：${PROJECT_ROOT}"
echo

echo "[1/3] tmux 后台任务"
if command -v tmux >/dev/null 2>&1 && tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
    tmux list-sessions -F '会话：#{session_name}，窗口数：#{session_windows}，创建时间：#{t:session_created}' \
        | grep "会话：${SESSION_NAME}，" || true
    echo "实时查看：bash scripts/watch-progress.sh"
else
    echo "当前没有名为 ${SESSION_NAME} 的 tmux 会话。"
fi
echo

echo "[2/3] OP-TEE QEMU 进程"
if pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then
    ps -C qemu-system-aarch64 -o pid=,etime=,%cpu=,%mem=,cmd= \
        | sed 's/^/  /'
else
    echo "当前没有运行中的 qemu-system-aarch64 进程。"
fi
echo

echo "[3/3] 最近日志"
LATEST_LOG=""
if [[ -d "$LOG_DIR" ]]; then
    LATEST_LOG="$(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' \
        | sort -nr | head -n 1 | cut -d' ' -f2-)"
fi

if [[ -n "$LATEST_LOG" ]]; then
    echo "文件：${LATEST_LOG}"
    echo "最后 10 行："
    tail -n 10 "$LATEST_LOG" | sed 's/^/  /'
else
    echo "目前还没有由 run-observable.sh 生成的日志。"
fi
