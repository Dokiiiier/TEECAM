#!/usr/bin/env bash
set -euo pipefail

SESSION=${COTE3_STAGE5_SESSION:-cote3-stage5}
ROOT=${COTE3_OPTEE_ROOT:-${HOME}/cote3-optee-qemu-v8}
RUN_TAG=${COTE3_STAGE5_RUN_TAG:-20260812-feature-ablation}
LOG_ROOT=${COTE3_STAGE5_LOG_ROOT:-$ROOT/cote3-stage5/$RUN_TAG/logs}

optee_window() {
    tmux list-windows -t "$SESSION" -F '#{window_index}:#{window_name}' \
        | awk -F: '$2 ~ /^OPTEE_/ {print $1; exit}'
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

show_status() {
    if ! tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "session=$SESSION status=ABSENT"
        pgrep -af '[/]qemu-system-aarch64' || true
        return 1
    fi
    echo "session=$SESSION status=RUNNING"
    tmux list-windows -t "$SESSION" -F 'window=#{window_index} name=#{window_name} panes=#{window_panes}'
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
    : >"$LOG_ROOT/qemu-monitor.log"
    : >"$LOG_ROOT/normal-world.log"
    : >"$LOG_ROOT/secure-world.log"
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
    [ -n "$window" ] || { echo "OP-TEE serial window did not appear" >&2; exit 1; }
    tmux pipe-pane -O -t "$SESSION:qemu.0" "cat >> '$LOG_ROOT/qemu-monitor.log'"
    tmux pipe-pane -O -t "$SESSION:$window.0" "cat >> '$LOG_ROOT/normal-world.log'"
    tmux pipe-pane -O -t "$SESSION:$window.1" "cat >> '$LOG_ROOT/secure-world.log'"
    echo "COTE3_STAGE5_QEMU_SESSION_READY"
    show_status
}

continue_qemu() {
    tmux send-keys -t "$SESSION:qemu.0" -l c
    tmux send-keys -t "$SESSION:qemu.0" Enter
    echo "COTE3_STAGE5_QEMU_CONTINUE_SENT"
}

login_guest() {
    send_normal_line root
    echo "COTE3_STAGE5_GUEST_LOGIN_SENT"
}

prepare_guest() {
    send_normal_line "echo COTE3_STAGE5_PREPARE_BEGIN; mkdir -p /mnt/host; mount | grep -q ' on /mnt/host ' || mount -t 9p -o trans=virtio,version=9p2000.L host /mnt/host"
    send_normal_line "g=/mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee; i=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon; mkdir -p /mnt/host/cote3-stage5/$RUN_TAG/raw; uname -m; file \$g; ls -l /dev/tee0 /dev/teepriv0 \$g \$i/experiments/stage5-feature-ablation.json"
    send_normal_line "if test \"\$(uname -m)\" = aarch64 -a -c /dev/tee0 -a -c /dev/teepriv0 -a -x \$g -a -f \$i/experiments/stage5-feature-ablation.json; then echo COTE3_STAGE5_GUEST_READY; else echo COTE3_STAGE5_GUEST_NOT_READY; fi"
    echo "COTE3_STAGE5_GUEST_PREPARE_SENT"
}

collect_data() {
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    send_normal_line "echo COTE3_STAGE5_COLLECTION_BEGIN; PYTHONPATH=$install_root python3 $install_root/run-qemu-experiments.py --config $install_root/experiments/stage5-feature-ablation.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-stage5-bundle --output /mnt/host/cote3-stage5/$RUN_TAG/raw --backend optee --stage stage5 --resume && echo COTE3_STAGE5_QEMU_COLLECTION_PASS"
    echo "COTE3_STAGE5_QEMU_COLLECTION_SENT"
}

verify_guest_models() {
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    analysis=/mnt/host/cote3-stage5/$RUN_TAG/analysis
    send_normal_line "echo COTE3_STAGE5_GUEST_PARITY_BEGIN; for name in base12 temporal16 repetition14 enhanced18; do PYTHONPATH=$install_root python3 $install_root/qemu-model-parity.py --stage stage5-\$name --model $analysis/models/iforest-\$name.json --vectors $analysis/parity-vectors-\$name.json --output $analysis/parity-guest-\$name.json || exit 1; done; echo COTE3_STAGE5_GUEST_PARITY_PASS"
    echo "COTE3_STAGE5_GUEST_PARITY_SENT"
}

smoke_data() {
    install_root=/mnt/host/cote3-bundle/rootfs/opt/cote3-mon
    send_normal_line "echo COTE3_STAGE5_SMOKE_BEGIN; PYTHONPATH=$install_root python3 $install_root/run-qemu-experiments.py --config $install_root/experiments/stage5-feature-ablation.json --gateway /mnt/host/cote3-bundle/rootfs/usr/bin/cote3-gateway-optee --bundle /mnt/host/cote3-bundle --runtime-bundle /tmp/cote3-stage5-smoke-v2-bundle --output /mnt/host/cote3-stage5/$RUN_TAG/smoke-v2/raw --backend optee --stage stage5-smoke --repeats 1 --duration 15 && echo COTE3_STAGE5_SMOKE_PASS"
    echo "COTE3_STAGE5_SMOKE_SENT"
}

stop_session() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux send-keys -t "$SESSION:qemu.0" -l q
        tmux send-keys -t "$SESSION:qemu.0" Enter
        sleep 1
        tmux kill-session -t "$SESSION" 2>/dev/null || true
    fi
    pgrep -f '[/]qemu-system-aarch64' >/dev/null 2>&1 && {
        echo "QEMU process remains after graceful stop" >&2
        return 1
    }
    echo "COTE3_STAGE5_QEMU_STOPPED"
}

case "${1:-}" in
    start) start_session ;;
    continue) continue_qemu ;;
    login) login_guest ;;
    prepare) prepare_guest ;;
    smoke) smoke_data ;;
    collect) collect_data ;;
    parity) verify_guest_models ;;
    status) show_status ;;
    stop) stop_session ;;
    *) echo "usage: $0 {start|continue|login|prepare|smoke|collect|parity|status|stop}" >&2; exit 2 ;;
esac
