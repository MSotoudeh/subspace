#!/bin/bash
#
#GIT_DIR="/opt/subspace"
systemctl stop subspace
GIT_DIR=$(pwd)
echo $GIT_DIR
GO_DIR="/usr/local/go"
export PATH="/usr/local/go/bin:$PATH";
export GOPATH="$GIT_DIR";
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH";
go version

apt-get update
apt-get install dirmngr qrencode

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt update
apt install -y wireguard

# Load modules.
modprobe wireguard
modprobe iptable_nat
modprobe ip6table_nat

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# gcc for cgo
apt-get install -y --no-install-recommends g++ gcc libc6-dev make pkg-config


# set golang version
GOLANG_VERSION='1.11.5'

# install golang

if [ ! -d "$GO_DIR" ]; then
  url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz";
  wget -O go.tgz "$url";
  tar -C /usr/local -xzf go.tgz;
  rm go.tgz;
fi

mkdir -p "$GOPATH/src" "$GOPATH/bin" #&& chmod -R 777 "$GOPATH"

cd $GOPATH

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

./bin/go-bindata --pkg main static/... templates/... email/...
go fmt
go vet --all

CGO_ENABLED=0
GOOS="linux"
GOARCH="amd64"
BUILD_VERSION="0.1"
#go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o /usr/bin/subspace-linux-amd64
go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o bin/subspace-linux-amd64

echo "GOPATH: "$GOPATH
cd $GOPATH

rm $PWD/bin/subspace
cp bin/subspace-linux-amd64 $PWD/bin/subspace
rm /usr/local/bin/subspace
cp bin/subspace-linux-amd64 /usr/local/bin/subspace

#cp conf.sh bin/conf.sh
#cp base.sh bin/base.sh

chmod +x /bin/ /usr/local/bin/subspace
sudo bash "scripts/sed.sh"
