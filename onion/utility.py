import socket
import sys
import time
import threading

HOST = "localhost"

R1_PORT = 50000
router1_mac = "R1"

N1_PORT = 51000
node1_ip = "1a"
node1_mac = "N1"

N2_PORT = 52000
node2_ip = "2a"
node2_mac = "N2"

N3_PORT = 53000
node3_ip = "3a"
node3_mac = "N3"

N4_PORT = 54000
node4_ip = "4a"
node4_mac = "N4"

N5_PORT = 55000
node5_ip = "5a"
node5_mac = "N5"

ROUTER_SOCKET = (HOST, R1_PORT)

arp_table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
    node3_ip: node3_mac,
    node4_ip: node4_mac,
    node5_ip: node5_mac,
}


arp_table_socket = {
    "router": None,
    node1_ip: None,
    node2_ip: None,
    node3_ip: None,
    node4_ip: None,
    node5_ip: None,
}


def handle_clients(arp_table_socket):
    for ip, client_socket in arp_table_socket.items():
        thread = threading.Thread(target=handle_client, args=(ip, client_socket))
        thread.start()


def handle_client(ip, conn):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Ready to receiving packets]\n")
    connected = True
    while connected:
        try:
            data = conn.recv(1024)
            if data:
                print("Received", repr(data))
        except:
            return False


def connect_to_router():
    try:
        ROUTER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as msg:
        ROUTER = None
        print(msg)
    try:
        ROUTER.connect(ROUTER_SOCKET)
        time.sleep(1)
        ROUTER.sendall(b"Hello, world")
    except OSError as msg:
        ROUTER.close()
        print(msg)
        ROUTER = None
    if ROUTER is None:
        print("could not open socket")
        sys.exit(1)
    return ROUTER
