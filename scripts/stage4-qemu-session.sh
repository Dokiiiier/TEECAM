#!/usr/bin/env bash
set -euo pipefail

SESSION=${COTE3_STAGE4_SESSION:-cote3-stage4}
ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE4_RUN_TAG:-20260719-formal-detection}
LOG_ROOT=${COTE3_STAGE4_LOG_ROOT:-$ROOT/cote3-stage4/$RUN_TAG/logs}

optee_window() {
    tmux list-windows -t "$SESSION" -F '#{window_index}:#{window_name}' \
        | awk -F: '$2 ~ /^OPTEE_/ {print $1; exit}'
}

show_status() {
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "session=$SESSION status=ABSENT"
        pgrep -af '[/]qemu-system-aarch64' || true
        return 1
    fi
    echo "session=$SESSION status=RUNNING"
    tmux list-windows -t "$SESSION" -F 'window=#{window_index} name=#{window_name} panes=#{window_panes}'
    tmux list-panes -a -t "$SESSION" \
        -F 'target=#{session_name}:#{window_index}.#{pane_index} command=#{pane_current_command}'
    pgrep -af '[/]qemu-system-aarch64' || true
}

start_session() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "refusing to replace existing session: $SESSION" >&2
        exit 1
    fi
    if pgrep -f '[/]qemu-system-aarch64' >/dev/null 2>&1; then
        echo "refusing to start while another qemu-system-aarch64 process exists" >&2
        exit 1
    fi
    mkdir -p "$LOG_ROOT"
    for log in qemu-monitor.log normal-world.log secure-world.log; do
        if [ -s "$LOG_ROOT/$log" ]; then
            printf '\n===== resumed %s =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$LOG_ROOT/$log"
        else
            : >"$LOG_ROOT/$log"
        fi
    done
    tmux new-session -d -s "$SESSION" -n qemu \
        "cd '$ROOT' && exec make -C build QEMU_VIRTFS_ENABLE=y QEMU_VIRTFS_AUTOMOUNT=y QEMU_VIRTFS_HOST_DIR='$ROOT' run-only"

    window=
    for _ in $(seq 1 150); do
        window=$(optee_window || true)
        if [ -n "$window" ] && tmux display-message -p -t "$SESSION:$window.1" '#{pane_index}' >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if [ -z "$window" ]; then
        tmux capture-pane -p -t "$SESSION:qemu.0" || true
        echo "OP-TEE serial window did not appear" >&2
        exit 1
    fi
    attach_log_pipes
    echo "COTE3_STAGE4_QEMU_SESSION_READY"
    show_status
}

attach_log_pipes() {
    window=$(optee_window)
    [ -n "$window" ] || { echo "OP-TEE serial window is absent" >&2; exit 1; }
    mkdir -p "$LOG_ROOT"
    touch "$LOG_ROOT/qemu-monitor.log" "$LOG_ROOT/normal-world.log" "$LOG_ROOT/secure-world.log"
    tmux pipe-pane -O -t "$SESSION:qemu.0" "cat >> '$LOG_ROOT/qemu-monitor.log'"
    tmux pipe-pane -O -t "$SESSION:$window.0" "cat >> '$LOG_ROOT/normal-world.log'"
    tmux pipe-pane -O -t "$SESSION:$window.1" "cat >> '$LOG_ROOT/secure-world.log'"
    echo "COTE3_STAGE4_LOG_PIPES_READY"
}

normal_target() {
    window=$(optee_window)
    [ -n "$window" ] || { echo "OP-TEE serial window is absent" >&2; exit 1; }
    printf '%s:%s.0\n' "$SESSION" "$window"
}

send_normal_line() {
    target=$(normal_target)
    tmux send-keys -t "$target" -l "$1"
    tmux send-keys -t "$target" Enter
}

continue_qemu() {
    tmux has-session -t "$SESSION" 2>/dev/null || { echo "session is absent" >&2; exit 1; }
    tmux send-keys -t "$SESSION:qemu.0" -l c
    tmux send-keys -t "$SESSION:qemu.0" Enter
    echo "COTE3_STAGE4_QEMU_CONTINUE_SENT"
}

login_guest() {
    send_normal_line root
    echo "COTE3_STAGE4_GUEST_LOGIN_SENT"
}

prepare_guest() {
    send_normal_line "i=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon; g=/mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee; m=/mnt/host/cote3-stage4/$RUN_TAG/analysis/models/iforest.json"
    send_normal_line "echo COTE3_STAGE4_PREPARE_BEGIN; mkdir -p /mnt/host; mount | grep -q ' on /mnt/host ' || mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/host"
    send_normal_line "mkdir -p /mnt/host/cote3-stage4/$RUN_TAG/raw /mnt/host/cote3-stage4/$RUN_TAG/performance/raw; uname -m; ls -l /dev/tee0 /dev/teepriv0 \$g \$m; command -v runc; command -v python3; command -v audit-client"
    send_normal_line "if test \"\$(uname -m)\" = aarch64 -a -c /dev/tee0 -a -c /dev/teepriv0 -a -x \$g -a -f \$m -a -f \$i/experiments/stage4-performance.json -a -f \$i/run-qemu-performance.py -a -f \$i/guest-online-monitor.py; then echo COTE3_STAGE4_GUEST_READY; else echo COTE3_STAGE4_GUEST_NOT_READY; fi"
    echo "COTE3_STAGE4_GUEST_PREPARE_SENT"
}

collect_data() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    command="echo COTE3_STAGE4_COLLECTION_BEGIN; PYTHONPATH=$install_root python3 $install_root/run-qemu-experiments.py --config $install_root/experiments/stage4-formal.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-experiment-bundle --output /mnt/host/cote3-stage4/$RUN_TAG/raw --backend optee --stage stage4 --resume && echo COTE3_STAGE4_QEMU_COLLECTION_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE4_QEMU_COLLECTION_SENT target=$target"
}

verify_guest_model() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    analysis=/mnt/host/cote3-stage4/$RUN_TAG/analysis
    command="PYTHONPATH=$install_root python3 $install_root/qemu-model-parity.py --stage stage4 --model $analysis/models/iforest.json --vectors $analysis/parity-vectors.json --output $analysis/parity-guest.json && echo COTE3_STAGE4_QEMU_PARITY_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE4_QEMU_PARITY_SENT target=$target"
}

collect_performance() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    command="echo COTE3_STAGE4_PERFORMANCE_BEGIN; PYTHONPATH=$install_root python3 $install_root/run-qemu-performance.py --config $install_root/experiments/stage4-performance.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-performance-bundle --output /mnt/host/cote3-stage4/$RUN_TAG/performance/raw --resume && echo COTE3_STAGE4_PERFORMANCE_QEMU_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE4_PERFORMANCE_SENT target=$target"
}

smoke_performance() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    command="echo COTE3_STAGE4_PERFORMANCE_SMOKE_BEGIN; PYTHONPATH=$install_root python3 $install_root/run-qemu-performance.py --config $install_root/experiments/stage4-performance.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-performance-smoke-bundle --output /mnt/host/cote3-stage4/$RUN_TAG/performance-smoke/raw --repeats 1 --duration 15 && echo COTE3_STAGE4_PERFORMANCE_SMOKE_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE4_PERFORMANCE_SMOKE_SENT target=$target"
}

stop_session() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux send-keys -t "$SESSION:qemu.0" -l q
        tmux send-keys -t "$SESSION:qemu.0" Enter
        sleep 1
        tmux kill-session -t "$SESSION" 2>/dev/null || true
    fi
    if pgrep -f '[/]qemu-system-aarch64' >/dev/null 2>&1; then
        echo "QEMU process remains after graceful stop" >&2
        return 1
    fi
    echo "COTE3_STAGE4_QEMU_STOPPED"
}

case "${1:-}" in
    start) start_session ;;
    continue) continue_qemu ;;
    login) login_guest ;;
    prepare) prepare_guest ;;
    status) show_status ;;
    logs) attach_log_pipes ;;
    collect) collect_data ;;
    parity) verify_guest_model ;;
    performance) collect_performance ;;
    performance-smoke) smoke_performance ;;
    stop) stop_session ;;
    *) echo "usage: $0 {start|continue|login|prepare|status|logs|collect|parity|performance|performance-smoke|stop}" >&2; exit 2 ;;
esac
