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

client_port=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f2- -d:)
server_port=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "Lis" | grep -oE '[0-9]+$')
service_host=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "http" | grep -oE '[^ ]+$')

client_port_line=$(sed = $PWD/handlers.go | sed 'N;s/\n/ /' | grep Endpoint | cut -f1 -d" ")
server_port_line=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "Lis" | cut -f1 -d" ")
service_host_line=$(sed = $PWD/scripts/conf.sh | sed 'N;s/\n/ /' | grep "http" | cut -f1 -d" ")

# echo "New Host: "$host
# echo "New Port: "$port
# echo "Old Host: "$service_host
# echo "Old Server port: "$server_port
# echo "Old Client port: "$client_port

echo ""
echo "Change: "$service_host" to "$host
echo "Change: "$server_port" to "$port
echo "Change: "$client_port" to "$port

# echo "sed -i "${service_host_line}s/${service_host}/${host}/g" $PWD/scripts/conf.sh"
# echo "sed -i "${server_port_line}s/${server_port}/${port}/g" $PWD/scripts/conf.sh"
# echo "sed -i "${client_port_line}s/${client_port}/${port}/g" $PWD/handlers.go"
sed -i "${service_host_line}s/${service_host}/${host}/g" $PWD/scripts/conf.sh
sed -i "${server_port_line}s/${server_port}/${port}/g" $PWD/scripts/conf.sh
sed -i "${client_port_line}s/${client_port}/${port}/g" $PWD/handlers.go

echo ""
echo "Changed: "$service_host" to "$host" in $PWD/scripts/conf.sh on line: "$service_host_line
echo "Changed: "$server_port" to "$port" in $PWD/scripts/conf.sh on line: "$server_port_line
echo "Changed: "$client_port" to "$port" $PWD/handlers.go on line: "$client_port_line
echo ""

sudo bash "scripts/conf.sh"
