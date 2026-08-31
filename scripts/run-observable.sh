#!/usr/bin/env bash

# 在 tmux 后台会话中运行一个命令，并把屏幕输出同步保存为日志。
# 用法：bash scripts/run-observable.sh <任务名称> <命令> [参数...]

set -euo pipefail

SESSION_NAME="${COTE3_TMUX_SESSION:-cote3mon}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${COTE3_LOG_DIR:-${PROJECT_ROOT}/artifacts/logs}"

usage() {
    cat <<'EOF'
用法：
  bash scripts/run-observable.sh <任务名称> <命令> [参数...]

示例：
  bash scripts/run-observable.sh hello bash -lc 'for i in 1 2 3; do echo "步骤 $i"; sleep 1; done'

说明：
  - 命令会在名为 cote3mon 的 tmux 后台会话中运行。
  - 屏幕输出会同时写入 artifacts/logs/ 下的时间戳日志。
  - 请不要把密码、令牌等秘密直接写进命令参数，因为命令会记入日志。
EOF
}

if (( $# < 2 )); then
    usage
    exit 2
fi

TASK_LABEL="$(printf '%s' "$1" | tr -c '[:alnum:]_.-' '_')"
shift

if [[ -z "$TASK_LABEL" ]]; then
    echo "错误：任务名称不能为空。" >&2
    exit 2
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "错误：尚未安装 tmux。请先安装后再运行此脚本。" >&2
    exit 1
fi

if tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
    cat >&2 <<EOF
错误：tmux 会话 ${SESSION_NAME} 已经存在。
请先运行 bash scripts/status.sh 查看它，或用 bash scripts/watch-progress.sh 进入查看。
EOF
    exit 1
fi

mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/$(date +%Y%m%d-%H%M%S)-${TASK_LABEL}.log"

# %q 会安全地转义路径和参数，再交给 tmux 中的 Bash 执行。
printf -v project_q '%q' "$PROJECT_ROOT"
printf -v log_q '%q' "$LOG_FILE"
printf -v command_q '%q ' "$@"
printf -v display_command '%q ' "$@"
printf -v task_line_q '%q' "[COTE3-Mon] 任务名称：${TASK_LABEL}"
printf -v command_line_q '%q' "[COTE3-Mon] 执行命令：${display_command}"

runner="cd ${project_q}; set -o pipefail; \
start_time=\$(date --iso-8601=seconds); \
printf '%s\\n' \"[COTE3-Mon] 开始时间：\${start_time}\" \
                 ${task_line_q} \
                 ${command_line_q} | tee ${log_q}; \
${command_q}2>&1 | tee -a ${log_q}; \
status=\${PIPESTATUS[0]}; \
end_time=\$(date --iso-8601=seconds); \
printf '%s\\n' \"[COTE3-Mon] 结束时间：\${end_time}\" \
                 \"[COTE3-Mon] 退出状态：\${status}\" | tee -a ${log_q}; \
printf '%s\\n' '[COTE3-Mon] 命令已结束。此窗口会保留，便于检查输出。' \
                 '[COTE3-Mon] 按 Ctrl+B，再按 D，可安全离开 tmux。'; \
exec bash"

tmux new-session -d -s "$SESSION_NAME" bash -lc "$runner"

cat <<EOF
任务已在后台启动。

任务名称：${TASK_LABEL}
tmux 会话：${SESSION_NAME}
日志文件：${LOG_FILE}

实时查看：bash scripts/watch-progress.sh
只看状态：bash scripts/status.sh
安全离开实时画面：先按 Ctrl+B，松开后再按 D。
EOF
