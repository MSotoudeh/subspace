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
if ! test -f /etc/wireguard/server/server.private ; then
    mkdir /etc/wireguard
    cd /etc/wireguard

    mkdir clients
    touch clients/null.conf # So you can cat *.conf safely
    mkdir peers
    touch peers/null.conf # So you can cat *.conf safely
    mkdir server
    mkdir config

    # Generate public/private server keys.
    wg genkey | tee server/server.private | wg pubkey > server/server.public
else
    echo -e "${YELLOW}> Server already exists!${NC}"
    echo ""
fi

cat <<WGSERVER >/etc/wireguard/server/wg0.conf
[Interface]
Address = 10.99.97.1/24
PrivateKey = $(cat /etc/wireguard/server/server.private)
ListenPort = 5555
PreUp = iptables -t nat -A POSTROUTING -s 10.99.97.0/24  -o ens18 -j MASQUERADE;
PostDown = iptables -t nat -D POSTROUTING -s 10.99.97.0/24  -o ens18 -j MASQUERADE;

WGSERVER
cat /etc/wireguard/peers/*/*.conf >>/etc/wireguard/server/wg0.conf
#find /etc/wireguard/peers/ -type f -name '*.conf' --exec cat {} + >>/etc/wireguard/server/server.conf

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
# ip link add wg0 type wireguard
# ip addr add 10.99.97.1/24 dev wg0
# wg setconf wg0 /etc/wireguard/server/wg0.conf
# ip link set wg0 up

# wg0 service
if test -f /etc/systemd/system/wg0.service ; then
    rm /etc/systemd/system/wg0.service
fi

if ! test -f /etc/systemd/system/wg0.service ; then
    touch /etc/systemd/system/wg0.service
    cat <<WIREGUARD_SERVICE >/etc/systemd/system/wg0.service
[Unit]
Description=Wireguard

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up /etc/wireguard/server/wg0.conf
ExecStop=/usr/bin/wg-quick down /etc/wireguard/server/wg0.conf

[Install]
WantedBy=multi-user.target
WIREGUARD_SERVICE
    systemctl daemon-reload
    systemctl enable wg0
    systemctl stop wg0
    systemctl start wg0
    systemctl status wg0
fi

# subspace service
if test -f /etc/systemd/system/subspace.service ; then
    rm /etc/systemd/system/subspace.service
fi

if ! test -f /etc/systemd/system/subspace.service ; then
    touch /etc/systemd/system/subspace.service
    cat <<SUBSPACE_SERVICE >/etc/systemd/system/subspace.service
[Unit]
Description=Subspace

[Service]
ExecStart=/usr/local/bin/subspace --debug --http-host localhost

[Install]
WantedBy=multi-user.target
SUBSPACE_SERVICE
    systemctl daemon-reload
    systemctl enable subspace
    systemctl start subspace
    systemctl status subspace
fi
