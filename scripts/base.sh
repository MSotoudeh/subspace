GIT_DIR = "/opt/subspace"
GO_DIR = "/usr/local/go"

apt-get update
apt-get install dirmngr

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

#update system and remove apt lists
apt-get install -y git
# clone git
if [ ! -d "$GIT_DIR" ]; then
  git clone https://github.com/BankaiNoJutsu/subspace /opt/subspace
fi

# set golang version
GOLANG_VERSION='1.11.5'

# install golang
if [ ! -d "$GO_DIR" ]; then
  url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz";
  wget -O go.tgz "$url";
  tar -C /usr/local -xzf go.tgz;
  rm go.tgz;
fi

export PATH="/usr/local/go/bin:$PATH";
go version

export GOPATH="/opt/subspace"
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
cd $GOPATH
