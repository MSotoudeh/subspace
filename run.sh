#!/bin/bash
#

GIT_DIR=$(pwd)
echo -e "${LIGHTBLUE}> Setting GO Path to: ${NC}"${YELLOW}$GIT_DIR"${NC}"
GO_DIR="/usr/local/go"
ARCH=$(dpkg --print-architecture)
echo -e "${LIGHTBLUE}> Actual arch is: ${NC}"${YELLOW}${ARCH}${NC}

export PATH="/usr/local/go/bin:$PATH";
export GOPATH="$GIT_DIR";
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH";

echo -e "${LIGHTBLUE}> Running go generate ${NC}"
go generate -v -x

echo -e "${LIGHTBLUE}> Running go get ${NC}"
go get -v \
    github.com/jteeuwen/go-bindata/... \
    github.com/dustin/go-humanize \
    github.com/julienschmidt/httprouter \
    github.com/sirupsen/logrus \
    github.com/gorilla/securecookie \
    golang.org/x/crypto/acme/autocert \
    golang.org/x/time/rate \
    golang.org/x/crypto/bcrypt \
    go.uber.org/zap \
    gopkg.in/gomail.v2 \
    github.com/ebuchman/go-shell-pipes \
    github.com/crewjam/saml \
    github.com/crewjam/saml/samlsp \
    github.com/skip2/go-qrcode

go build
