#!/bin/bash

while [ "$1" != "" ] || [ "$2" != "" ]; do
    case $1 in
        -t | --token )
            shift
            Token="$1"
            ;;
    esac
    case $1 in
        -d | --domain )
            shift
            Domain="$1"
            ;;
    esac
    case $2 in
        -t | --token )
            shift
            Token="$2"
            ;;
    esac
    case $2 in
        -d | --domain )
            shift
            Domain="$2"
            ;;
    esac
    shift
done

if [ "$Domain" == '' ] || [ "$Token" == '' ]; then
  echo -e "${RED}Please specify domain and token with -d and -t ${NC}"
elif [ "$Domain" != '' ] || [ "$Token" != '' ]; then
  echo "Crontab: "$(/usr/bin/crontab -l | { /bin/cat; echo "0 12 * * * /usr/bin/curl -s https://www.duckdns.org/update?domains=${Domain}&token=${Token}&ip="; } | /usr/bin/crontab - )
fi

return

echo "/usr/bin/crontab -l | { /bin/cat; echo 0 12 * * * /usr/bin/curl -s https://www.duckdns.org/update?domains=${Domain}&token=${Token}&ip=; } | /usr/bin/crontab -"
echo "Domain: "${Domain}
echo "Token: "${Token}
