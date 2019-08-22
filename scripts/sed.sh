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

sudo bash "scripts/conf.sh"
