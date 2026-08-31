#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo $0" >&2
    exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    acpica-tools autoconf automake bc bison build-essential ccache cpio curl \
    device-tree-compiler e2tools expect flex gdisk git libattr1-dev libcap-ng-dev \
    libfdt-dev libftdi1-dev libglib2.0-dev libgmp3-dev libgnutls28-dev \
    libhidapi-dev libmpc-dev libncurses-dev libpixman-1-dev libssl-dev libtool \
    libusb-1.0-0-dev mtools netcat-openbsd ninja-build python3-cryptography \
    python3-pip python3-pyelftools python3-serial python3-tomli repo rsync swig unzip uuid-dev \
    wget xdg-utils xterm xz-utils zlib1g-dev
