import socket
import sys
import time
from Packet import Packet
from utility import (
    broadcast_data,
    manage_protocol,
    print_node_information,
    choose_protocol,
    retrieve_packet,
    send_data,
    start_receiver,
)
import threading
from ctypes import c_int
from multiprocessing import Value


def handle_client(ip, conn):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Ready to receiving packets]\n")
    connected = True
    while connected:
        received_packet = retrieve_packet(conn)
        if received_packet is False:
            print(f"{ip} disconnected")
            connected = False
            conn.close()
            break

        if received_packet and received_packet.print_packet_integrity_status(
            node_mac, node_ip
        ):
            connected = manage_protocol(
                arp_table_socket, received_packet, node_ip, node_mac, online
            )
        else:
            print("[Checking!] Packet Dropped")


# def handle_clients(arp_table_socket):
#     thread = threading.Thread(
#         target=handle_client, args=(node3_ip, arp_table_socket[node3_ip])
#     )
#     thread.start()


def start_listening(node_server):
    global arp_table_socket

    print(f"listening on {node_server.getsockname()}\n")
    node_server.listen(1)
    while arp_table_socket[node3_ip] is None:
        conn, addr = node_server.accept()
        if arp_table_socket[node3_ip] is None:
            arp_table_socket[node3_ip] = conn
            print("Node 3 is online")

    thread = threading.Thread(
        target=handle_client, args=(node3_ip, arp_table_socket[node3_ip])
    )
    thread.start()


node_ip = "2a"
node_mac = "N2"

router_mac = "R2"

HOST = "localhost"
PORT = 8200
ROUTER = (HOST, PORT)
node = None

NODE2_PORT = 8500
NODE2 = (HOST, NODE2_PORT)
node_server = None

node3_ip = "3a"
node3_mac = "N3"

arp_table_mac = {node3_ip: node3_mac}

node3 = None

arp_table_socket = {
    "router": node,
    node3_ip: node3,
}

time.sleep(1)

print("[STARTING] node 2 is starting...")
print_node_information(node_ip, node_mac)

try:
    node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    node_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    arp_table_socket["router"] = node

except OSError as msg:
    node = None
    node_server = None
    print(msg)
try:
    online = Value(c_int, 1)
    node_server.bind(NODE2)

    node.connect(ROUTER)
    arp_table_socket["router"] = node

    print("[LISTENING]")
    listening_thread = threading.Thread(
        target=start_listening, args=(node_server,), daemon=True
    )
    listening_thread.start()

    print("[Connecting] Node 2 is connected to router")
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
        if protocol in [0, 1, 2]:
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
