import socket
import time
from Packet import Packet
from utility import print_node_information

node_ip = "0x2A"
node_mac = "N2"
router = ("localhost", 8200)
node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
node.connect(router)

print_node_information(node_ip, node_mac)

while True:
    received_message = node.recv(1024)

    received_packet_header = received_message.decode("utf-8")
    if received_packet_header != "":
        received_packet = Packet(received_packet_header)

        print("\nThe packed received:")
        received_packet.print_packet_information()

        received_packet.print_packet_integrity_status(node_mac, node_ip)
