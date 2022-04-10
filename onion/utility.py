import socket
import sys
import time
import threading
import random
import copy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pathlib import Path

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

def broadcast_data(arp_table_socket_client, packet_header):
    is_success = True
    for socket_conn in arp_table_socket_client.values():
        send_data(socket_conn, packet_header)
        if not send_data:
            is_success = False
    return is_success


def send_data(socket_conn, packet_header):
    try:
        socket_conn.sendall(packet_header)
        return True
    except ConnectionError:
        return False


def generate_onion_path(src, dest):
    ip_dict = copy.deepcopy(ip_address_port_dict)
    ip_dict.pop(src)
    ip_dict.pop(dest)
    order = random.sample(range(3), 3)
    ip_list = list(ip_dict)
    onion_path = [ip_list[order[0]], ip_list[order[1]],ip_list[order[2]]]
    return onion_path

def generate_keys(path):
    for node in path:
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        public_dir = Path("keys")
        public_dir.mkdir(exist_ok=True)
        file_out = open("keys/{node}.bin".format(node=node), "wb")
        file_out.write(key + iv)
        file_out.close()
    return

def prepare_onion_packet(path, message):
    message = bytes(message, 'utf-8')
    for n in range(len(path) - 1, -1, -1):
        key_file = open("keys/{node}.bin".format(node=path[n]), "rb").read()
        key = key_file[0:16]
        iv = key_file[16:]
        # print('current msg: ', message, ' length ', len(message))
        print("\nEncrypting with {n} key ...".format(n=path[n]))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(pad(message, AES.block_size))
 

        if n != 0:
            next_node = path[n - 1]
            message = bytes(next_node, "utf-8") + encrypted_message
        else:
            message = encrypted_message
        # print('next message to encrypt', message)
    encrypted_packet = message
    return encrypted_packet

def decrypt(data, node): #data does NOT include next hop addr
    key_file = open("keys/{node}.bin".format(node=node), "rb").read()
    key = key_file[0:16]
    iv = key_file[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    print('decrypted', decrypted, 'length of decrypted', len(decrypted))
    unpadded_packet = unpad(decrypted, AES.block_size)
    return (unpadded_packet[0:2], unpadded_packet[2:])  # Returns (Next Addr, Msg)

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
                    if data[0:2].decode('utf-8') in list(ip_address_port_dict):
                        current_node_ip = data[0:2].decode('utf-8')
                        encrypted_packet = data[2:]
                        next_addr, decrypted_data = decrypt(encrypted_packet, current_node_ip)
                        print('Next onion node\t', next_addr)
                        print('Decrypted_data\t', decrypted_data)
                        print("Length of decrypted data\t", len(decrypted_data))
                        packet_to_send = next_addr + decrypted_data
                        broadcast_data(arp_table_socket_client, packet_to_send)
                    else:
                        print("\nReceived message:\t", repr(data))          

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




