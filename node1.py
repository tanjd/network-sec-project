import socket
from Packet import Packet
from utility import print_node_information

node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
node.bind(("localhost", 8000))
node.listen(2)
node_ip = "0x1A"
node_mac = "N1"
router_mac = "R1"
print_node_information(node_ip, node_mac)
while True:
    routerConnection, address = node.accept()
    if routerConnection is not None:
        print("\n" + str(routerConnection) + "\n")
        break

payload = "MY DATA"
source_ip = node_ip
destination_ip = "0x2A"
protocol = 0
source_mac = node_mac
destination_mac = router_mac

packet = Packet(
    source_ip, destination_ip, source_mac, destination_mac, protocol, payload
)
packet.print_packet_information()
packet_header = packet.create_packet_header()

routerConnection.send(bytes(packet_header, "utf-8"))
