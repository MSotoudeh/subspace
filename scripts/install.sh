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

echo -e "${LIGHTBLUE}> Stopping service ${NC}"
systemctl stop subspace
GIT_DIR=$(pwd)
echo -e "${LIGHTBLUE}> Setting GO Path to: ${NC}"${YELLOW}$GIT_DIR"${NC}"
GO_DIR="/usr/local/go"
export PATH="/usr/local/go/bin:$PATH";
export GOPATH="$GIT_DIR";
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH";

echo -e "${LIGHTBLUE}> Actual go version is: ${NC}"${YELLOW}$(go version)${NC}

echo -e "${LIGHTBLUE}> Running apt update... ${NC}"
apt-get update >/dev/null 2>&1
echo -e "${LIGHTBLUE}> Install dirmngr and qrencode ${NC}"
apt-get install dirmngr qrencode >/dev/null 2>&1

echo -e "${LIGHTBLUE}> Install WireGuard ${NC}"
echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt update  >/dev/null 2>&1
apt install -y wireguard >/dev/null 2>&1

echo -e "${LIGHTBLUE}> Load modules ${NC}"
# Load modules.
modprobe wireguard
modprobe iptable_nat
modprobe ip6table_nat

echo -e "${LIGHTBLUE}> Enable IP forwarding ${NC}"
# Enable IP forwarding
printf ${WHITE}
echo ">> "$(sysctl -w net.ipv4.ip_forward=1)
echo ">> "$(sysctl -w net.ipv6.conf.all.forwarding=1)

echo -e "${LIGHTBLUE}> Install build tools ${NC}"
# gcc for cgo
apt-get install -y --no-install-recommends g++ gcc libc6-dev make pkg-config >/dev/null 2>&1

# set golang version
GOLANG_VERSION='1.11.5'

# install golang
if [ ! -d "$GO_DIR" ]; then
  echo -e "${LIGHTBLUE}> Installing GO to /usr/local ${NC}"
  url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz";
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
    gopkg.in/gomail.v2

GODEBUG="netdns=go http2server=0"

echo -e "${LIGHTBLUE}> Running go-bindata ${NC}"
./bin/go-bindata --pkg main static/... templates/... email/...
go fmt
go vet --all

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
sudo bash "scripts/sed.sh"
