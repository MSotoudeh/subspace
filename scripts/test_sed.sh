new_server_port=9999
new_client_host=badaboum
new_client_port=9999

server_port_line=$(sed = /etc/wireguard/server/wg0.conf | sed 'N;s/\n/ /' | grep "Lis" | cut -f1 -d" " | tail -n1)
server_port=$(sed = /etc/wireguard/server/wg0.conf | sed 'N;s/\n/ /' | grep "Lis" | grep -oE '[0-9]+$' | tail -n1)
client_port_lines=$(sed = /etc/wireguard/clients/*/*.conf | sed 'N;s/\n/ /' | grep "Endpoint " | cut -f1 -d' ')
client_ports=$(sed = /etc/wireguard/clients/*/*.conf | sed 'N;s/\n/ /' | grep Endpoint | cut -f2- -d: | cut -f2- -d, | cut -f1 -d' ')
client_hosts=$(sed = /etc/wireguard/clients/*/*.conf | sed 'N;s/\n/ /' | grep "Endpoint =" | cut -f1 -d: | cut -f4 -d ' ')
client_port=$(sed = /etc/wireguard/clients/*/*.conf | sed 'N;s/\n/ /' | grep Endpoint | cut -f2- -d: | cut -f2- -d, | cut -f1 -d' ' | tail -n1)
client_host=$(sed = /etc/wireguard/clients/*/*.conf | sed 'N;s/\n/ /' | grep "Endpoint =" | cut -f1 -d: | cut -f4 -d ' ' | tail -n1)


echo ""

echo "sed -i "${server_port_line}s/${server_port}/${new_server_port}/g" /etc/wireguard/server/wg0.conf"
#echo "sed -i "${client_port_lines}s/${client_ports}/${new_client_port}/g" /etc/wireguard/clients/*/*.conf"
#echo "sed -i "${client_port_lines}s/${client_hosts}/${new_client_host}/g" /etc/wireguard/clients/*/*.conf"

echo "sed -i "s/${client_port}/${new_client_port}/g" /etc/wireguard/clients/*/*.conf"
echo "sed -i "s/${client_host}/${new_client_host}/g" /etc/wireguard/clients/*/*.conf"

echo ""

#echo $server_port_line
#echo $server_port
#echo $client_port_lines
#echo $client_ports
#echo $client_hosts
