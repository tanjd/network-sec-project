import socket
import time
from Packet import Packet
from utility import print_node_information, start_client_response, start_protocol
import threading

node_ip = "0x2A"
node_mac = "N2"
router = ("localhost", 8200)
node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)


def handle_client():
    connected = True
    while connected:
        received_message = node.recv(1024)
        received_packet_header = received_message.decode("utf-8")
        if received_packet_header:
            received_packet = Packet(received_packet_header)

            print("\nThe packet received:")
            received_packet.print_packet_information()

            received_packet.print_packet_integrity_status(node_mac, node_ip)

            # destination_ip = received_packet.source_ip
            # destination_mac = received_packet.source_mac

            protocol = start_client_response()

            start_protocol(protocol, received_packet, node)


def start():
    # try catch this connecting
    node.connect(router)
    print("[LISTENING] Node 2 is connected to router")

    thread = threading.Thread(target=handle_client)
    thread.start()
    print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] node 2 is starting...")
print_node_information(node_ip, node_mac)
start()
