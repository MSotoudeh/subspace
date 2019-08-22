#!/bin/bash
#

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
ip link add wg0 type wireguard
ip addr add 10.99.97.1/24 dev wg0
wg setconf wg0 /etc/wireguard/server/server.conf
ip link set wg0 up
