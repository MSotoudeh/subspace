#!/bin/bash
#
# Colors to use for output
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[1;166;4m'
RED='\033[1;31m'
GREEN='\033[1;32m'
LIGHTBLUE='\033[1;36m'
NC='\033[0m' # No Color

# Check if user is root or sudo
if ! [ $(id -u) = 0 ]; then echo -e "Please run this script as sudo or root"; exit 1 ; fi

# WireGuard (10.99.97.0/24)
#
# /etc/wireguard
# folder each: server, clients, peers, config
#
if ! test -f /etc/wireguard/server.private ; then
    mkdir /etc/wireguard
    cd /etc/wireguard

    mkdir clients
    touch clients/null.conf # So you can cat *.conf safely
    mkdir peers
    touch peers/null.conf # So you can cat *.conf safely

    # Generate public/private server keys.
    wg genkey | tee server.private | wg pubkey > server.public
else
    echo -e "${YELLOW}> Server already exists!${NC}"
    echo ""
fi

cat <<WGSERVER >/etc/wireguard/server.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server.private)
ListenPort = 80

WGSERVER
cat /etc/wireguard/peers/*.conf >>/etc/wireguard/server.conf

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
ip link add wg0 type wireguard
ip addr add 10.99.97.1/24 dev wg0
ip addr add fd00::10:97:1/112 dev wg0
wg setconf wg0 /etc/wireguard/server.conf
ip link set wg0 up

# subspace service
if test -f /etc/systemd/system/subspace.service ; then
    rm /etc/systemd/system/subspace.service
fi

if ! test -f /etc/systemd/system/subspace.service ; then
    touch /etc/systemd/system/subspace.service
    cat <<SSERVICE >/etc/systemd/system/subspace.service
[Unit]
Description=Subspace

[Service]
ExecStart=/usr/local/bin/subspace --debug --http-host dev.local2

[Install]
WantedBy=multi-user.target
SSERVICE
    systemctl daemon-reload
    systemctl enable subspace
    systemctl start subspace
    systemctl status subspace
fi
