import socket
import time
from Packet import Packet

router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.bind(("localhost", 8100))

router_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_send.bind(("localhost", 8200))

router_mac = "R1"

server = ("localhost", 8000)

node1_ip = "0x1A"
node1_mac = "N1"
node2_ip = "0x2A"
node2_mac = "N2"

router_send.listen(4)
node1 = None
node2 = None

while node2 is None:
    client, address = router_send.accept()

    if node2 is None:
        node2 = client
        print("node 2 is online")

arp_table_socket = {node1_ip: node1, node2_ip: node2}
arp_table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
}
print(arp_table_mac)

router.connect(server)

while True:
    received_message = router.recv(1024)
    received_packet_header = received_message.decode("utf-8")
    if received_packet_header != "":

        received_packet = Packet(received_packet_header)

        print("\nThe packed received:")
        received_packet.print_packet_information()

        packet_header = received_packet.create_forward_packet(
            router_mac, arp_table_mac[received_packet.destination_ip]
        )

        destination_socket = arp_table_socket[received_packet.destination_ip]

        destination_socket.send(bytes(packet_header, "utf-8"))
        time.sleep(2)
