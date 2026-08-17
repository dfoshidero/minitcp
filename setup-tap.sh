#!/usr/bin/env bash
# Plug in the fake Ethernet cable Linux and MiniTCP share.
# tap0 dies when the container restarts, so run this before cargo run.
set -euo pipefail

USER_NAME="$(id -un)"

if ! ip link show tap0 >/dev/null 2>&1; then
  # `user` means cargo run can attach as you, without sudo.
  sudo ip tuntap add dev tap0 mode tap user "$USER_NAME"
fi

if ! ip -4 addr show dev tap0 | grep -q '10.0.0.1/24'; then
  sudo ip addr add 10.0.0.1/24 dev tap0
fi

sudo ip link set dev tap0 up
ip addr show tap0
ip route
