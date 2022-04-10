import socket
import sys
import time
from utility import (
    print_node_information,
    choose_protocol,
    send_data,
    start_receiver
)
import threading
from ctypes import c_int
from multiprocessing import Value


node_ip = "1a"
node_mac = "N1"

router_mac = "R1"

HOST = "localhost"
PORT = 8100
router = (HOST, PORT)
node = None

arp_table_mac = {}
arp_table_socket = {"router": node}

time.sleep(1)

print("[STARTING] node 1 is starting...")
print_node_information(node_ip, node_mac)

try:
    node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    node = None
    print(msg)
try:
    online = Value(c_int, 1)
    node.connect(router)
    arp_table_socket["router"] = node

    print("[Connecting] Node 1 is connected to router")
    thread = threading.Thread(
        target=start_receiver,
        args=(arp_table_socket, node, node_ip, node_mac, online),
        daemon=True,
    )
    thread.start()

    time.sleep(1)

    while online.value:
        destination_mac = router_mac
        protocol = choose_protocol()
        if protocol in [0, 1, 2, 3]:
            if protocol == 3:
                sender_ip = input("\nEnter IP Address to use for spoofing: ")
            else:
                sender_ip = node_ip
            answer = input("\nDo you want to send the sample data (y|n): ")
            if answer == "y":
                data = "MY DATA"
            else:
                data = input("\nEnter message to send: ")
            ip_addr = input("\n Enter IP Address to ping: ")

            try:
                send_data(
                    node, sender_ip, ip_addr, node_mac, destination_mac, protocol, data
                )
            except ConnectionError:
                online = False
        else:
            print("TBC")

        time.sleep(1)

except OSError as msg:
    node.close()
    print(msg)
    node = None
if node is None:
    print("could not open socket")
    sys.exit(1)
