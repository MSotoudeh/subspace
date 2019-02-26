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

# set golang version
GOLANG_VERSION='1.11.5'

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
    gopkg.in/gomail.v2

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
sudo bash "scripts/sed.sh"
