#!/bin/bash
#
# Colors to use for output
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[1;166;4m'
RED='\033[1;31m'
GREEN='\033[1;32m'
LIGHTBLUE='\033[1;36m'
WHITE='\e[38;5;255m'
BLACK='\033[5;232m'
NC='\033[0m' # No Color

# Check if user is root or sudo
if ! [ $(id -u) = 0 ]; then echo -e "Please run this script as sudo or root"; exit 1 ; fi

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
        -h | --host )
            shift
            host="$1"
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
        -h | --host )
            shift
            host="$2"
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
    if test "$host" == '' || test "$port" == ''
    then
      echo -e "${RED}Please specify host and port with -h and -p ${NC}"
      exit 0
    fi
fi

echo -e "${LIGHTBLUE}> Stopping service ${NC}"
systemctl stop subspace
# subspace service
echo -e "${LIGHTBLUE}> Creating Service /etc/systemd/system/subspace.service${NC}"
if test -f /etc/systemd/system/subspace.service ; then
    rm /etc/systemd/system/subspace.service
fi

if ! test -f /etc/systemd/system/subspace.service ; then
    touch /etc/systemd/system/subspace.service
    cat <<SUBSPACE_SERVICE >/etc/systemd/system/subspace.service
[Unit]
Description=Subspace

[Service]
ExecStartPre=/usr/local/etc/wg_service.sh
ExecStart=/usr/local/bin/subspace --debug --http-host $host

[Install]
WantedBy=multi-user.target
SUBSPACE_SERVICE

systemctl daemon-reload

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

echo -e "${LIGHTBLUE}> Enable IPV4 firewall forwarding rules ${NC}"
# # Enable IP forwarding
if ! /sbin/iptables -t nat --check POSTROUTING -s 10.99.97.0/24 -j MASQUERADE >/dev/null 2>&1; then
	echo -e "${LIGHTBLUE}>> NAT rule enabled ${NC}"$(/sbin/iptables -t nat --append POSTROUTING -s 10.99.97.0/24 -j MASQUERADE)
else
	echo -e "${YELLOW}>> NAT already there ${NC}"
fi

if ! /sbin/iptables --check FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
	echo -e "${LIGHTBLUE}>> Forward 1 rule enabled ${NC}"$(/sbin/iptables --append FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT)
else
        echo -e "${YELLOW}>> Forward 1 already there ${NC}"
fi

if ! /sbin/iptables --check FORWARD -s 10.99.97.0/24 -j ACCEPT >/dev/null 2>&1; then
	echo -e "${LIGHTBLUE}>> Forward 2 rule enabled ${NC}"$(/sbin/iptables --append FORWARD -s 10.99.97.0/24 -j ACCEPT)
else
        echo -e "${YELLOW}>> Forward 2 already there ${NC}"
fi

echo -e "${LIGHTBLUE}> Enable IPV4 DNS Leak Protection ${NC}"
# # Enable DNS Leak Protection
if ! /sbin/iptables -t nat --check OUTPUT -s 10.99.97.0/16 -p udp --dport 53 -j DNAT --to 10.99.97.1:53 >/dev/null 2>&1; then
    echo -e "${LIGHTBLUE}>> DNS Leak 1 rule enabled ${NC}"$(/sbin/iptables -t nat --append OUTPUT -s 10.99.97.0/16 -p udp --dport 53 -j DNAT --to 10.99.97.1:53)
else
        echo -e "${YELLOW}>> DNS Leak 1 already there ${NC}"
fi

if ! /sbin/iptables -t nat --check OUTPUT -s 10.99.97.0/16 -p tcp --dport 53 -j DNAT --to 10.99.97.1:53 >/dev/null 2>&1; then
    echo -e "${LIGHTBLUE}>> DNS Leak 2 rule enabled ${NC}"$(/sbin/iptables -t nat --append OUTPUT -s 10.99.97.0/16 -p tcp --dport 53 -j DNAT --to 10.99.97.1:53)
else
        echo -e "${YELLOW}>> DNS Leak 2 already there ${NC}"
fi

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
    github.com/ebuchman/go-shell-pipes \
    github.com/jasonlvhit/gocron

GODEBUG="netdns=go http2server=0"

echo -e "${LIGHTBLUE}> Running go-bindata ${NC}"
if [ $ARCH == "armhf" ]
then
./bin/go-bindata-arm --pkg main static/... templates/... email/... >/dev/null 2>&1
go fmt >/dev/null 2>&1
go vet --all >/dev/null 2>&1
fi

if [ $ARCH == "amd64" ]
then
./bin/go-bindata --pkg main static/... templates/... email/... >/dev/null 2>&1
go fmt >/dev/null 2>&1
go vet --all >/dev/null 2>&1
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

if ! test -f /etc/wireguard/server/server.private ; then
    echo -e "${LIGHTBLUE}> Creating Server!${NC}"

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
fi

#cat <<WGSERVER >/etc/wireguard/server/server.conf
cat <<WGSERVER >/etc/wireguard/server/wg0.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/server/server.private)
ListenPort = $port

WGSERVER
#cat /etc/wireguard/peers/*/*.conf >>/etc/wireguard/server/server.conf
cat /etc/wireguard/peers/*/*.conf >>/etc/wireguard/server/wg0.conf
#find /etc/wireguard/peers/ -type f -name '*.conf' --exec cat {} + >>/etc/wireguard/server/server.conf

if ip link show wg0 >/dev/null 2>&1; then
    ip link del wg0 >/dev/null 2>&1
fi
ip link add wg0 type wireguard >/dev/null 2>&1
ip addr add 10.99.97.1/24 dev wg0 >/dev/null 2>&1
#wg setconf wg0 /etc/wireguard/server/server.conf >/dev/null 2>&1
wg setconf wg0 /etc/wireguard/server/wg0.conf >/dev/null 2>&1

ip link set wg0 up >/dev/null 2>&1

# copy wg_service start script
echo -e "${LIGHTBLUE}> Copying scripts/wg_service.sh to /usr/local/etc/wg_service.sh${NC}"
cp scripts/wg_service.sh /usr/local/etc/wg_service.sh

# chmod +x it
echo -e "${LIGHTBLUE}> chmod +x on /usr/local/etc/wg_service.sh${NC}"
chmod +x /usr/local/etc/wg_service.sh

echo -e "${LIGHTBLUE}> Final service restart${NC}"
    systemctl daemon-reload
    systemctl enable subspace
    systemctl start subspace
    systemctl restart subspace
    systemctl is-active --quiet subspace && echo -e "${GREEN}> Subspace is running${NC}" || echo -e "${RED}> Subspace is NOT running${NC}"
fi
