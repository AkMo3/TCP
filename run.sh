#!/bin/sh
cargo b --release
CARGO_TARGET_DIR=$("pwd")/target/
$CARGO_TARGET_DIR/release/trust &
pid=$!
sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/trust
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid

