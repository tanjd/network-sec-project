import socket
import sys
import time
from Packet import Packet
from utility import (
    print_node_information,
    start_client_response,
    start_protocol,
    send_sample_packet,
    start_receiver,
)
import threading


node_ip = "0x3A"
node_mac = "N3"

router_mac = "R2"

HOST = "localhost"
PORT = 8200
router = (HOST, PORT)
node = None
time.sleep(1)

print("[STARTING] node 3 is starting...")
print_node_information(node_ip, node_mac)

try:
    node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    node = None
    print(msg)
try:
    node.connect(router)
    print("[Connecting] Node 3 is connected to router")
    thread = threading.Thread(
        target=start_receiver, args=(node, node_ip, node_mac), daemon=True
    )
    thread.start()

    online = True
    while online:
        answer = input("\nDo you want to send the sample data (y|n): ")
        if answer == "y":
            destination_mac = router_mac
            send_sample_packet(node, node_ip, "0x1A", node_mac, destination_mac)
        protocol = start_client_response()

        if protocol == 3:
            print("Just listening")
        if protocol == 4:
            print("Terminating node")
            online = False
            node.close()
except OSError as msg:
    node.close()
    print(msg)
    node = None
if node is None:
    print("could not open socket")
    sys.exit(1)
