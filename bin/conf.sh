#!/bin/bash
#
# Check if user is root or sudo
if ! [ $(id -u) = 0 ]; then echo -e "${ORANGE}Please run this script as sudo or root${NC}"; exit 1 ; fi

# set vars
while [[ "$host" = '' ]]; do
      echo -e "> Which host?"
      read host
done
SUBSPACE_HTTP_HOST=$host

while [[ "$port" = '' ]]; do
      echo -e "> Which port?"
      read port
done
SUBSPACE_HTTP_PORT=$port

# WireGuard (10.99.97.0/24)
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
    echo "Server already exists!"
fi

cat <<WGSERVER >/etc/wireguard/server.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server.private)
ListenPort = ${SUBSPACE_HTTP_PORT}

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
ExecStart=/opt/subspace/bin/subspace --debug --http-host "${SUBSPACE_HTTP_HOST}"

[Install]
WantedBy=multi-user.target
SSERVICE
    systemctl daemon-reload
    systemctl enable subspace
    systemctl start subspace
    systemctl status subspace
fi

# subspace service log
# if ! test -f /etc/systemd/system/subspace-log.service ; then
#     mkdir /etc/sv/subspace/log
#     mkdir /etc/sv/subspace/log/main
#     cat <<SLOGSERVICE >/etc/sv/subspace/log/run
# #!/bin/sh
# exec svlogd -tt ./main
# SLOGSERVICE
#     chmod +x /etc/sv/subspace/log/run
#     ln -s /etc/sv/subspace /etc/service/subspace
# fi
