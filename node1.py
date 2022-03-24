import socket
import sys
import time
from Packet import Packet
from utility import (
    print_node_information,
    choose_recipient,
    choose_protocol,
    send_data,
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
        destination_mac = router_mac
        protocol = choose_protocol()
        if protocol in [0,1,2]:
            ip_addr = choose_recipient()
            answer = input("\nDo you want to send the sample data (y|n): ")
            if answer == "y":
                data = "MY DATA"
            else:
                data = input("\nEnter a message: ")
            send_data(node, node_ip, ip_addr, node_mac, destination_mac, protocol, data)
        else:
                print("TBC")
   
except OSError as msg:
    node.close()
    print(msg)
    node = None
if node is None:
    print("could not open socket")
    sys.exit(1)
