import socket
from utility import create_packet

node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
node.bind(("localhost", 8000))
node.listen(2)
node_ip = "0x1A"
node_mac = "N1"
router_mac = "R1"

while True:
    routerConnection, address = node.accept()
    if routerConnection is not None:
        print(routerConnection)
        break

payload = "MY DATA"
source_ip = node_ip
destination_ip = "0x2A"
protocol = 0
source_mac = node_mac
destination_mac = router_mac


packet = create_packet(
    source_ip, destination_ip, source_mac, destination_mac, protocol, payload
)
print(packet)
routerConnection.send(bytes(packet, "utf-8"))
