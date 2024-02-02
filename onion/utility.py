import copy
import random
import socket
import sys
import threading
import time
from os import urandom
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = "localhost"

MAX_PACKET_LENGTH = 256
PADDING = b"/"

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

table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
    node3_ip: node3_mac,
    node4_ip: node4_mac,
    node5_ip: node5_mac,
}


table_socket = {
    "router": None,
    node1_ip: None,
    node2_ip: None,
    node3_ip: None,
    node4_ip: None,
    node5_ip: None,
}

table_socket_client = {
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


# SOCKET CONNECTIONS
def connect_to_router():
    try:
        ROUTER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as msg:
        ROUTER = None
        print(msg)
    try:
        ROUTER.connect(ROUTER_SOCKET)
        time.sleep(1)
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
            connected = True
        except OSError as msg:
            NODE.close()
            print(f"{msg} : attempting to reconnect to {ip_address}")
            NODE = None
    if NODE is None:
        print("could not open socket")
        return False
    return NODE


def broadcast_data(table_socket_client, packet, node_ip):
    is_success = True

    # table_socket_client.pop(node_ip)
    for client in table_socket_client:
        socket_conn = table_socket_client[client]
        if client != node_ip:
            send_data(socket_conn, packet)
            if not send_data:
                is_success = False

    return is_success


def send_data(socket_conn, packet):
    try:
        socket_conn.sendall(packet)
        return True
    except ConnectionError:
        return False


# ONION 'ETHERNET'
def generate_onion_path(src, dest):
    ip_dict = copy.deepcopy(ip_address_port_dict)
    ip_dict.pop(src)
    ip_dict.pop(dest)
    order = random.sample(range(3), 3)
    ip_list = list(ip_dict)
    onion_path = [ip_list[order[0]], ip_list[order[1]], ip_list[order[2]], dest]
    return onion_path


def generate_keys(path):
    for node in path:
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        public_dir = Path("keys")
        public_dir.mkdir(exist_ok=True)
        file_out = open(f"keys/{node}.bin", "wb")
        file_out.write(key + iv)
        file_out.close()
    return


def padding(payload, MAX_PACKET_LENGTH, PADDING):
    return payload + PADDING * (MAX_PACKET_LENGTH - len(payload))


def unpadding(payload, PADDING):
    index = payload.index(PADDING + PADDING)
    unpadded_payload = payload[0:index]
    return unpadded_payload


def prepare_onion_packet(path, message, dest):
    message = bytes(dest + message, "utf-8")
    for n in range(len(path) - 1, -1, -1):
        node_ip = path[n]
        key_file = open(f"keys/{node_ip}.bin", "rb").read()
        key = key_file[0:16]
        iv = key_file[16:]
        print("\nCurrent message", message)
        print(f"Encrypting with {node_ip} key ...")
        cipher = AES.new(key, AES.MODE_CBC, iv)

        encrypted_message = cipher.encrypt(pad(message, AES.block_size))
        print("encrypted message", encrypted_message, " length ", len(encrypted_message))
        dest_addr = path[n]
        message = bytes(dest_addr, "utf-8") + encrypted_message
    encrypted_packet = padding(message, MAX_PACKET_LENGTH, PADDING)
    return encrypted_packet


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


def decrypt(data, node):  # data does NOT include next hop addr
    key_file = open(f"keys/{node}.bin", "rb").read()
    key = key_file[0:16]
    iv = key_file[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    unpadded_packet = unpad(decrypted, AES.block_size)
    return (unpadded_packet[0:2], unpadded_packet[2:])  # Returns (Next Addr, Msg)


# LISTENING SOCKETS
def handle_clients(node_ip, table_socket, is_router):
    for ip, client_socket in table_socket.items():
        thread = threading.Thread(target=handle_client, args=(node_ip, ip, client_socket, is_router))
        thread.start()


def handle_client(my_ip, ip, conn, is_router):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Ready to receive packets]\n")
    connected = True
    while connected:
        try:
            data = conn.recv(1024)
            if data:
                if is_router:
                    print("Received", repr(data))
                else:
                    print(f"\n[BROADCAST RECEIVED]:", data)

                    unpadded_data = unpadding(data, PADDING)
                    src_ip = unpadded_data[0:2].decode("utf-8")
                    dest_ip = unpadded_data[2:4].decode("utf-8")

                    if dest_ip == my_ip:
                        packet = unpadded_data[4:]
                        time.sleep(0.5)
                        print(
                            "\n [ONION ETHERNET] Received packet from {src}:\t{encrypted_packet}".format(
                                src=src_ip, encrypted_packet=packet
                            )
                        )

                        print("\n[ONION ETHERNET] Decrypting packet ...")
                        time.sleep(0.5)
                        next_dest, decrypted_data = decrypt(packet, my_ip)
                        next_dest = next_dest.decode("utf-8")

                        if next_dest == my_ip:  # Receiving Node decrypts plaintext msg
                            plaintext = decrypted_data.decode("utf-8")
                            if plaintext:
                                print(
                                    "\n", "*" * 40, "\n[ONION ETHERNET] Received message: {msg}".format(msg=plaintext)
                                )

                        else:  # Packet Decryption and forwarding
                            packet_header = bytes(my_ip + next_dest, "utf-8")
                            packet_to_send = padding(packet_header + decrypted_data, MAX_PACKET_LENGTH, PADDING)

                            print("\n[ONION ETHERNET]Decrypted_data:\t", decrypted_data)
                            print(
                                "\n[ONION ETHERNET] Payload Length:\t",
                                len(decrypted_data),
                            )
                            print(
                                "\n[ONION ETHERNET] Packet Destination:\t{dest}".format(dest=next_dest),
                            )
                            print(
                                "\n[ONION ETHERNET] Sending packet:\t {packet}".format(packet=packet_to_send),
                            )
                            broadcast_data(table_socket_client, packet_to_send, my_ip)
                    else:  # Drop
                        print("[DROPPED] Packet dropped")

        except ConnectionError:
            return False
