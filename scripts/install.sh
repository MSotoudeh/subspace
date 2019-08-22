#!/bin/bash
#
# Colors to use for output
#printf '\e[48;5;232m Background color: black\n' && printf '\e[38;5;255m Foreground color: white\n'
#printf '\e[48;5;021m Background color: blue\n' && printf '\e[38;5;255m Foreground color: white\n'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[1;166;4m'
RED='\033[1;31m'
GREEN='\033[1;32m'
LIGHTBLUE='\033[1;36m'
WHITE='\e[38;5;255m'
BLACK='\033[5;232m'
NC='\033[0m' # No Color

interactive=""

while [ "$1" != "" ] || [ "$2" != "" ]; do
    case $1 in
        -i | --interactive )
            shift
            interactive="yes"
            ;;
    esac
    case $1 in
        -p | --port )
            shift
            port="$1"
            interactive="yes"
            ;;
    esac
    case $1 in
        -d | --domain )
            shift
            domain="$1"
            interactive="yes"
            ;;
    esac
    case $2 in
        -p | --port )
            shift
            port="$2"
            interactive="yes"
            ;;
    esac
    case $2 in
        -d | --domain )
            shift
            domain="$2"
            interactive="yes"
            ;;
    esac
    shift
done

if test "$interactive" != 'yes'
then
    echo -e "${RED}For interactive mode please use -i, or use -h | --help${NC}"
    exit 0
fi

if test "$interactive" == 'yes'
then
    if test "$domain" == '' || test "$port" == ''
    then
      echo -e "${RED}Please specify domain and port with -d and -p ${NC}"
      exit 0
    fi
fi

echo -e "${LIGHTBLUE}> Stopping service ${NC}"
systemctl stop subspace
GIT_DIR=$(pwd)
echo -e "${LIGHTBLUE}> Setting GO Path to: ${NC}"${YELLOW}$GIT_DIR"${NC}"
GO_DIR="/usr/local/go"
ARCH=$(dpkg --print-architecture)
echo -e "${LIGHTBLUE}> Actual arch is: ${NC}"${YELLOW}${ARCH}${NC}

export PATH="/usr/local/go/bin:$PATH";
export GOPATH="$GIT_DIR";
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH";

echo -e "${LIGHTBLUE}> Actual go version is: ${NC}"${YELLOW}$(go version)${NC}

echo -e "${LIGHTBLUE}> Running apt update... ${NC}"
apt-get update >/dev/null 2>&1
echo -e "${LIGHTBLUE}> Install dirmngr, qrencode, dnsutils (dig) and curl${NC}"
apt-get install dirmngr qrencode dnsutils curl -y >/dev/null 2>&1

echo -e "${LIGHTBLUE}> Install WireGuard ${NC}"
echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt update  >/dev/null 2>&1
apt install -y wireguard >/dev/null 2>&1

echo -e "${LIGHTBLUE}> Load modules ${NC}"
# Load modules.
/sbin/modprobe wireguard
/sbin/modprobe iptable_nat
/sbin/modprobe ip6table_nat

echo -e "${LIGHTBLUE}> Enable IP forwarding ${NC}"
# Enable IP forwarding
printf ${WHITE}
echo ">> "$(/sbin/sysctl -w net.ipv4.ip_forward=1)
echo ">> "$(/sbin/sysctl -w net.ipv6.conf.all.forwarding=1)
#echo ">> "$(sysctl -w net.ipv4.ip_forward=1)
#echo ">> "$(sysctl -w net.ipv6.conf.all.forwarding=1)

echo -e "${LIGHTBLUE}> Enable IPV4 firewall forwarding rules ${NC}"
# # Enable IP forwarding
echo ">> NAT"$(/sbin/iptables -t nat --append POSTROUTING -s 10.99.97.0/24 -j MASQUERADE)
echo ">> Forward 1"$(/sbin/iptables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT)
echo ">> Forward 2"$(/sbin/iptables --append FORWARD -s 10.99.97.0/24 -j ACCEPT)

echo -e "${LIGHTBLUE}> Install build tools ${NC}"
# gcc for cgo
apt-get install -y --no-install-recommends g++ gcc libc6-dev make pkg-config >/dev/null 2>&1

# set golang version
GOLANG_VERSION='1.12.9'
#GOLANG_VERSION='1.11.5'

# install golang
if [ ! -d "$GO_DIR" ]; then
  echo -e "${LIGHTBLUE}> Installing GO to /usr/local ${NC}"
  if [ $ARCH == "armhf" ]
  then
    url="https://dl.google.com/go/go{GOLANG_VERSION}.linux-armv6l.tar.gz";
  elif [ $ARCH == "amd64" ]
  then
    url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz";
  fi
  wget -O go.tgz "$url"
  tar -C /usr/local -xzf go.tgz
  rm go.tgz
else
  echo -e "${LIGHTBLUE}> GO is already installed to /usr/local ${NC}"
fi

mkdir -p "$GOPATH/src" "$GOPATH/bin" #&& chmod -R 777 "$GOPATH"

cd $GOPATH

echo -e "${LIGHTBLUE}> Running go get ${NC}"
go get -v \
    github.com/jteeuwen/go-bindata/ \
    github.com/dustin/go-humanize \
    github.com/julienschmidt/httprouter \
    github.com/Sirupsen/logrus \
    github.com/gorilla/securecookie \
    golang.org/x/crypto/acme/autocert \
    golang.org/x/time/rate \
    golang.org/x/crypto/bcrypt \
    go.uber.org/zap \
    gopkg.in/gomail.v2 \
    github.com/jasonlvhit/gocron

GODEBUG="netdns=go http2server=0"

echo -e "${LIGHTBLUE}> Running go-bindata ${NC}"
if [ $ARCH == "armhf" ]
then
./bin/go-bindata-arm --pkg main static/... templates/... email/...
go fmt
go vet --all
fi

if [ $ARCH == "amd64" ]
then
./bin/go-bindata --pkg main static/... templates/... email/...
go fmt
go vet --all
fi

CGO_ENABLED=0
GOOS="linux"
GOARCH="amd64"
BUILD_VERSION="0.1"
echo -e "${LIGHTBLUE}> Building subspace ${NC}"
go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o bin/subspace-linux-amd64

cd $GOPATH

echo -e "${LIGHTBLUE}> Updating subspace binary in /usr/local/bin ${NC}"
rm /usr/local/bin/subspace
cp bin/subspace-linux-amd64 /usr/local/bin/subspace

chmod +x /bin/ /usr/local/bin/subspace

#sudo bash "scripts/sed.sh"

# set vars
client_port=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f2- -d: | cut -f2- -d,)
server_port=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "Lis" | grep -oE '[0-9]+$')
service_host=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "http" | grep -oE '[^ ]+$')

client_port_lines=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d' ')
client_port_line1=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d' ' | (echo $client_port_lines | cut -f1 -d' '))
client_port_line2=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d' ' | (echo $client_port_lines | cut -f2 -d' '))
#client_port_line1=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d" ")
#client_port_line2=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d" " | cut -f2- -d" ")
server_port_line=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "Lis" | cut -f1 -d" ")
service_host_line=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "http" | cut -f1 -d" ")

# Colors to use for output
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[1;166;4m'
RED='\033[1;31m'
GREEN='\033[1;32m'
LIGHTBLUE='\033[1;36m'
NC='\033[0m' # No Color

echo ""
echo -e "${LIGHTBLUE}> Actual host is: ${NC}"${YELLOW}$service_host${NC}
echo ""
while [[ "$host" = "" ]]; do
	echo -e "${YELLOW}> Which new host? (\"keep\" or leave empty to keep actual)${NC}"
	read host
	if [[ "$host" = "keep" || "$host" = "" ]]; then
		echo -e "${GREEN}> Keeping old host: "${YELLOW}$service_host${NC}
		host=$service_host
	else
		echo -e "${YELLOW}> Change: "$service_host" to "$host${NC}
	fi
done
#SUBSPACE_HTTP_HOST=$host

echo ""
echo -e "${LIGHTBLUE}> Actual port is: ${NC}"${YELLOW}$server_port${NC}
echo ""
while [[ "$port" = "" ]]; do
	echo -e "${YELLOW}> Which new port? (\"keep\" or leave empty to keep actual)${NC}"
	read port
	if [[ "$port" = "keep" || "$port" = "" ]]; then
        	echo -e "${GREEN}> Keeping old port: "${YELLOW}$server_port${NC}
        	port=$server_port
	else
		echo -e "${YELLOW}> Change: "$server_port" to "$port${NC}
	fi
done

#echo "New Host: "$host
#echo "New Port: "$port
#echo "Old Host: "$service_host
#echo "Old Server port: "$server_port
#echo "Old Client port: "$client_port

#echo ""
#echo "Change: "$service_host" to "$host
#echo "Change: "$server_port" to "$port
#echo "Change: "$client_port" to "$port

#echo "sed -i "${service_host_line}s/${service_host}/${host}/g" $PWD/scripts/conf.sh"
#echo "sed -i "${server_port_line}s/${server_port}/${port}/g" $PWD/scripts/conf.sh"
#echo "sed -i "${client_port_line1}s/${client_port}/${port}/g" $PWD/handlers.go"
#echo "sed -i "${client_port_line2}s/${client_port}/${port}/g" $PWD/handlers.go"

sed -i "${service_host_line}s/${service_host}/${host}/g" $PWD/scripts/conf.sh
sed -i "${server_port_line}s/${server_port}/${port}/g" $PWD/scripts/conf.sh
sed -i "${client_port_line1}s/${client_port}/${port}/g" $PWD/handlers.go
sed -i "${client_port_line2}s/${client_port}/${port}/g" $PWD/handlers.go

echo ""
echo -e "${GREEN}> Changed Host from "$service_host" to "$host" in $PWD/scripts/conf.sh on line: "$service_host_line${NC}
echo -e "${GREEN}> Changed Server Port from "$server_port" to "$port" in $PWD/scripts/conf.sh on line: "$server_port_line${NC}
echo -e "${GREEN}> Changed Client Port1 from "$client_port" to "$port" $PWD/handlers.go on line: "$client_port_line1${NC}
echo -e "${GREEN}> Changed Client Port2 from "$client_port" to "$port" $PWD/handlers.go on line: "$client_port_line2${NC}
echo ""

#sudo bash "scripts/conf.sh"

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

cat <<WGSERVER >/etc/wireguard/server/server.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server/server.private)
ListenPort = 5555

WGSERVER
cat /etc/wireguard/peers/*/*.conf >>/etc/wireguard/server/server.conf
#find /etc/wireguard/peers/ -type f -name '*.conf' --exec cat {} + >>/etc/wireguard/server/server.conf

if ip link show wg0 2>/dev/null; then
    ip link del wg0
fi
ip link add wg0 type wireguard
ip addr add 10.99.97.1/24 dev wg0
wg setconf wg0 /etc/wireguard/server/server.conf
ip link set wg0 up

# # wg0 service
# if test -f /etc/systemd/system/wg0.service ; then
#     rm /etc/systemd/system/wg0.service
# fi
#
# if ! test -f /etc/systemd/system/wg0.service ; then
#     touch /etc/systemd/system/wg0.service
#     cat <<WIREGUARD_SERVICE >/etc/systemd/system/wg0.service
# [Unit]
# Description=Wireguard
#
# [Service]
# Type=oneshot
# RemainAfterExit=yes
# ExecStart=/usr/bin/wg-quick up /etc/wireguard/server/wg0.conf
# ExecStop=/usr/bin/wg-quick down /etc/wireguard/server/wg0.conf
#
# [Install]
# WantedBy=multi-user.target
# WIREGUARD_SERVICE
#     systemctl daemon-reload
#     systemctl enable wg0
#     systemctl stop wg0
#     systemctl start wg0
#     systemctl status wg0
# fi

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
