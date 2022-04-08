import socket
import sys
import time
from utility import (
    print_node_information,
    choose_protocol,
    send_data,
    start_receiver,
)
import threading


node_ip = "3a"
node_mac = "N3"

router_mac = "R2"

HOST = "localhost"
PORT = 8200
router = (HOST, PORT)
node2 = None

NODE2_PORT = 8500
node = (HOST, NODE2_PORT)
time.sleep(1)


try:
    node2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

except OSError as msg:
    node2 = None
    print(msg)
try:
    node2.connect(node)
    print("[Connecting] Node 3 is connected to node 2")
    time.sleep(5)
    ip_addr = "2a"
    data = "MY DATA"
    packet_sent = send_data(node2, node_ip, ip_addr, node_mac, "N2", 0, data)


except OSError as msg:
    node2.close()
    print(msg)
    node2 = None
if node2 is None:
    print("could not open socket")
    sys.exit(1)
