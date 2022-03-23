import socket
import sys
import time
from Packet import Packet
from utility import (
    print_node_information,
    choose_protocol,
    send_sample_packet,
    start_receiver,
)
import threading


node_ip = "0x1A"
node_mac = "N1"

router_mac = "R1"

HOST = "localhost"
PORT = 8100
router = (HOST, PORT)
node = None

time.sleep(1)

print("[STARTING] node 1 is starting...")
print_node_information(node_ip, node_mac)

try:
    node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    node = None
    print(msg)
try:
    node.connect(router)
    print("[Connecting] Node 1 is connected to router")
    thread = threading.Thread(
        target=start_receiver, args=(node, node_ip, node_mac), daemon=True
    )
    thread.start()

    online = True
    while online:
        answer = input("\nDo you want to send the sample data (y|n): ")
        if answer == "y":
            protocol = choose_protocol()
            destination_mac = router_mac
            send_sample_packet(
                node, node_ip, "0x2A", node_mac, destination_mac, protocol
            )

        # do checking of protocol here then call the different protocol methods instead of calling one big method to then split what method to do

except OSError as msg:
    node.close()
    print(msg)
    node = None
if node is None:
    print("could not open socket")
    sys.exit(1)
