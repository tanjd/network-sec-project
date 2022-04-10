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

arp_table_socket_client = {
    "router": None,
    node1_ip: None,
    node2_ip: None,
    node3_ip: None,
    node4_ip: None,
    node5_ip: None,
}

ip_address_port_dict = {
    node1_ip: N1_PORT,
    node2_ip: N2_PORT,
    node3_ip: N3_PORT,
    node4_ip: N4_PORT,
    node5_ip: N5_PORT,
}


def get_ip_address(node_index):
    if node_index == 1:
        return node1_ip
    if node_index == 2:
        return node2_ip
    if node_index == 3:
        return node3_ip
    if node_index == 4:
        return node4_ip
    if node_index == 5:
        return node5_ip


def handle_clients(arp_table_socket, is_router=False):
    for ip, client_socket in arp_table_socket.items():
        thread = threading.Thread(
            target=handle_client, args=(ip, client_socket, is_router)
        )
        thread.start()


def handle_client(ip, conn, is_router):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Ready to receiving packets]\n")
    connected = True
    while connected:
        try:
            data = conn.recv(1024)
            if data:
                if is_router:
                    print("Received", repr(data))
                else:
                    print("Received node data: ", repr(data))
                    # print packet
                    # decode packet
                    # retrieve next destination_ip
                    # broadcast new packet with new destination_ip
        except ConnectionError:
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


def connect_to_node(node_ip, ip_address):
    PORT = ip_address_port_dict[ip_address]
    connected = False

    while not connected:
        time.sleep(3)
        try:
            NODE = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as msg:
            NODE = None
            print(msg)
        try:
            NODE.connect((HOST, PORT))
            time.sleep(1)
            NODE.sendall(b"Message from " + bytes(node_ip, "utf-8"))
            connected = True
        except OSError as msg:
            NODE.close()
            print(f"{msg} : attempting to reconnect to {ip_address}")
            NODE = None
    if NODE is None:
        print("could not open socket")
        return False
    return NODE
