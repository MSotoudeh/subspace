#!/bin/bash
#

cp /etc/wireguard/server/server_clean.conf /etc/wireguard/server/server.conf

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
ip link add wg0 type wireguard
ip addr add 10.99.97.1/24 dev wg0
wg setconf wg0 /etc/wireguard/server/server.conf
ip link set wg0 up

/sbin/iptables -t nat --append POSTROUTING -s 10.99.97.0/24 -j MASQUERADE
/sbin/iptables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables --append FORWARD -s 10.99.97.0/24 -j ACCEPT
