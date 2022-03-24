import socket
import sys
import time
from Packet import Packet
from utility import (
    print_node_information,
    choose_protocol,
    choose_recipient,
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
node = None
time.sleep(1)

firewall_rules = {"A": [], "D": ["ALL"]}


def display_firewall_rules(firewall_rules):
    print("Current firewall rules: ")
    for key in firewall_rules.keys():
        print(f" {key} : {firewall_rules[key]}")


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
        target=start_receiver,
        args=(node, node_ip, node_mac, firewall_rules),
        daemon=True,
    )
    thread.start()

    online = True
    while online:
        destination_mac = router_mac
        protocol = choose_protocol()
        if protocol in [0, 1, 2]:
            answer = input("\nDo you want to send the sample data (y|n): ")
            if answer == "y":
                data = "MY DATA"
            else:
                data = input("\nEnter message to send: ")

            ip_addr = input("\n Enter IP Address to ping: ")
            packet_sent = send_data(
                node, node_ip, ip_addr, node_mac, destination_mac, protocol, data
            )
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
