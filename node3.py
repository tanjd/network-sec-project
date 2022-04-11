import socket
import sys
import time
from utility import (
    broadcast_data,
    print_node_information,
    choose_protocol,
    start_receiver,
    configure_firewall,
)
import threading
from ctypes import c_int
from multiprocessing import Value


node_ip = "3a"
node_mac = "N3"

router_mac = "R2"

HOST = "localhost"
PORT = 8200
ROUTER = (HOST, PORT)
router = None

NODE2_PORT = 8500
NODE2 = (HOST, NODE2_PORT)
node_client = None

node2_ip = "2a"
node2_mac = "N2"

arp_table_mac = {node2_ip: node2_mac}

node2 = None

arp_table_socket = {
    "router": router,
    node2_ip: node2,
}

time.sleep(1)

firewall_rules = {"A": ["ALL"], "D": []}


def display_firewall_rules(firewall_rules):
    print("Current firewall rules: ")
    for key in firewall_rules.keys():
        print(f" {key} : {firewall_rules[key]}")


print("[STARTING] node 3 is starting...")
print_node_information(node_ip, node_mac)

try:
    router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    node2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    router = None
    print(msg)
try:
    online = Value(c_int, 1)
    router.connect(ROUTER)
    arp_table_socket["router"] = router

    node2.connect(NODE2)
    arp_table_socket[node2_ip] = node2

    print("\n[Connecting] Node 3 is connected to router")
    thread = threading.Thread(
        target=start_receiver,
        args=(arp_table_socket, router, node_ip, node_mac, online, firewall_rules),
        daemon=True,
    )
    thread.start()

    print("\n[Connecting] Node 3 is connected to node 2")
    thread = threading.Thread(
        target=start_receiver,
        args=(arp_table_socket, node2, node_ip, node_mac, online, firewall_rules),
        daemon=True,
    )
    thread.start()

    time.sleep(1)

    while online.value:
        protocol = choose_protocol()
        if protocol in [0, 1, 2, 3, 4]:
            if protocol == 3:
                sender_ip = input("\nEnter IP Address to use for spoofing: ")
            else:
                sender_ip = node_ip
            answer = input("\nDo you want to send the sample data (y|n): ")
            if answer == "y":
                data = "MY DATA"
            else:
                data = input("\nEnter message to send: ")

            destination_ip = input("\n Enter IP Address to ping: ")

            destination_mac = router_mac
            if destination_ip in arp_table_mac.keys():
                destination_mac = arp_table_mac[destination_ip]

            broadcast_data(
                arp_table_socket,
                node_ip,
                destination_ip,
                node_mac,
                destination_mac,
                protocol,
                data,
            )
        elif protocol in [5]:
            configure_firewall(firewall_rules)
        else:
            print("TBC")

        time.sleep(1)

except OSError as msg:
    router.close()
    node2.close()
    print(msg)
    arp_table_socket["router"] = None
    arp_table_socket["node2_ip"] = None
if router or node2 is None:
    print("could not open socket")
    sys.exit(1)
