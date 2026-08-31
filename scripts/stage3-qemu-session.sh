#!/usr/bin/env bash
set -euo pipefail

SESSION=${COTE3_STAGE3_SESSION:-cote3-stage3}
ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
LOG_ROOT="$ROOT/cote3-stage3/logs"
RUN_TAG=${COTE3_STAGE3_RUN_TAG:-20260718-ai-smoke}

optee_window() {
    tmux list-windows -t "$SESSION" -F '#{window_index}:#{window_name}' \
        | awk -F: '$2 ~ /^OPTEE_/ {print $1; exit}'
}

show_status() {
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "session=$SESSION status=ABSENT"
        pgrep -a qemu-system-aarch64 || true
        return 1
    fi
    echo "session=$SESSION status=RUNNING"
    tmux list-windows -t "$SESSION" -F 'window=#{window_index} name=#{window_name} panes=#{window_panes}'
    tmux list-panes -a -t "$SESSION" \
        -F 'target=#{session_name}:#{window_index}.#{pane_index} command=#{pane_current_command}'
    pgrep -a qemu-system-aarch64 || true
}

start_session() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "refusing to replace existing session: $SESSION" >&2
        exit 1
    fi
    if pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then
        echo "refusing to start while another qemu-system-aarch64 process exists" >&2
        exit 1
    fi
    mkdir -p "$LOG_ROOT"
    : >"$LOG_ROOT/qemu-monitor.log"
    : >"$LOG_ROOT/normal-world.log"
    : >"$LOG_ROOT/secure-world.log"
    tmux new-session -d -s "$SESSION" -n qemu \
        "cd '$ROOT' && exec make -C build QEMU_VIRTFS_ENABLE=y QEMU_VIRTFS_AUTOMOUNT=y QEMU_VIRTFS_HOST_DIR='$ROOT' run-only"

    window=
    for _ in $(seq 1 100); do
        window=$(optee_window || true)
        [ -n "$window" ] && break
        sleep 0.1
    done
    if [ -z "$window" ]; then
        tmux capture-pane -p -t "$SESSION:qemu.0" || true
        echo "OP-TEE serial window did not appear" >&2
        exit 1
    fi
    tmux pipe-pane -o -t "$SESSION:qemu.0" "cat >> '$LOG_ROOT/qemu-monitor.log'"
    tmux pipe-pane -o -t "$SESSION:$window.0" "cat >> '$LOG_ROOT/normal-world.log'"
    tmux pipe-pane -o -t "$SESSION:$window.1" "cat >> '$LOG_ROOT/secure-world.log'"
    echo "COTE3_STAGE3_QEMU_SESSION_READY"
    show_status
}

continue_qemu() {
    tmux has-session -t "$SESSION" 2>/dev/null || { echo "session is absent" >&2; exit 1; }
    tmux send-keys -t "$SESSION:qemu.0" -l c
    tmux send-keys -t "$SESSION:qemu.0" Enter
    echo "COTE3_STAGE3_QEMU_CONTINUE_SENT"
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

login_guest() {
    send_normal_line root
    echo "COTE3_STAGE3_GUEST_LOGIN_SENT"
}

prepare_guest() {
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    gateway=/mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee
    command="echo COTE3_STAGE3_PREPARE_BEGIN; mkdir -p /mnt/host; { mount | grep -q ' on /mnt/host ' || mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/host; }; uname -m; ls -l /dev/tee0 /dev/teepriv0; command -v runc; command -v python3; ls -l $install_root/experiments/stage3-smoke.json $install_root/qemu-model-parity.py $gateway; mkdir -p /mnt/host/cote3-stage3/$RUN_TAG/raw; if test \"\$(uname -m)\" = aarch64 && test -c /dev/tee0 && test -c /dev/teepriv0 && command -v runc >/dev/null && command -v python3 >/dev/null && test -f $install_root/experiments/stage3-smoke.json && test -f $install_root/qemu-model-parity.py && test -x $gateway && test -d /mnt/host/cote3-stage3/$RUN_TAG/raw; then echo COTE3_STAGE3_GUEST_READY; else echo COTE3_STAGE3_GUEST_NOT_READY; fi"
    send_normal_line "$command"
    echo "COTE3_STAGE3_GUEST_PREPARE_SENT"
}

collect_data() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    command="PYTHONPATH=$install_root python3 $install_root/run-qemu-experiments.py --config $install_root/experiments/stage3-smoke.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-experiment-bundle --output /mnt/host/cote3-stage3/$RUN_TAG/raw --backend optee && echo COTE3_STAGE3_QEMU_COLLECTION_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE3_QEMU_COLLECTION_SENT target=$target"
}

verify_guest_model() {
    target=$(normal_target)
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    analysis=/mnt/host/cote3-stage3/$RUN_TAG/analysis
    command="PYTHONPATH=$install_root python3 $install_root/qemu-model-parity.py --model $analysis/models/iforest.json --vectors $analysis/parity-vectors.json --output $analysis/parity-guest.json && echo COTE3_STAGE3_QEMU_PARITY_PASS"
    send_normal_line "$command"
    echo "COTE3_STAGE3_QEMU_PARITY_SENT target=$target"
}

stop_session() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux send-keys -t "$SESSION:qemu.0" -l q
        tmux send-keys -t "$SESSION:qemu.0" Enter
        sleep 1
        tmux kill-session -t "$SESSION" 2>/dev/null || true
    fi
    if pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then
        echo "QEMU process remains after graceful stop" >&2
        return 1
    fi
    echo "COTE3_STAGE3_QEMU_STOPPED"
}

case "${1:-}" in
    start) start_session ;;
    continue) continue_qemu ;;
    login) login_guest ;;
    prepare) prepare_guest ;;
    status) show_status ;;
    collect) collect_data ;;
    parity) verify_guest_model ;;
    stop) stop_session ;;
    *) echo "usage: $0 {start|continue|login|prepare|status|collect|parity|stop}" >&2; exit 2 ;;
esac
