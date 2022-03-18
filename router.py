import socket
import sys
import time
import threading
from Packet import Packet


def handle_client(ip, conn):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Ready to receiving packets]\n")
    connected = True
    while connected:
        received_message = conn.recv(1024)
        received_packet_header = received_message.decode("utf-8")
        if received_packet_header:
            received_packet = Packet(received_packet_header)
            print("\nThe packet received:")
            received_packet.print_packet_information()

            if received_packet.destination_mac == router1_mac:
                source_mac = router2_mac
                sending_conn = r2_arp_table_socket[received_packet.destination_ip]
            else:
                source_mac = router1_mac
                sending_conn = r1_arp_table_socket[received_packet.destination_ip]

            packet_header = received_packet.create_forward_packet(
                source_mac, arp_table_mac[received_packet.destination_ip]
            )
            sending_conn.send(bytes(packet_header, "utf-8"))
    conn.close()


def handle_clients(arp_table_socket):
    # print(arp_table_socket)
    for ip, conn in arp_table_socket.items():
        thread = threading.Thread(target=handle_client, args=(ip, conn))
        thread.start()


def start_listening(router):
    print(f"listening on {router.getsockname()}\n")
    router.listen()
    global r1_arp_table_socket
    global r2_arp_table_socket
    global node1
    global node2
    global node3
    while node1 is None and router.getsockname()[1] == R1_PORT:
        conn, addr = router.accept()
        if node1 is None:
            node1 = conn
            print("Node 1 is online")

    while (node2 is None or node3 is None) and router.getsockname()[1] == R2_PORT:
        conn, addr = router.accept()
        if node2 is None:
            node2 = conn
            print("Node 2 is online")
        elif node3 is None:
            node3 = conn
            print("Node 3 is online")

    if router.getsockname()[1] == R1_PORT:
        r1_arp_table_socket = {node1_ip: node1}
        handle_clients(r1_arp_table_socket)
    else:
        r2_arp_table_socket = {node2_ip: node2, node3_ip: node3}
        handle_clients(r2_arp_table_socket)


HOST = "localhost"

R1_PORT = 8100
R2_PORT = 8200

router1_mac = "R1"
router2_mac = "R2"

node1_ip = "0x1A"
node1_mac = "N1"

node2_ip = "0x2A"
node2_mac = "N2"

node3_ip = "0x3A"
node3_mac = "N3"

arp_table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
    node3_ip: node3_mac,
}
node1 = None
node2 = None
node3 = None

r1_arp_table_socket = {node1_ip: node1}
r2_arp_table_socket = {node2_ip: node2, node3_ip: node3}
time.sleep(1)

print("[STARTING] router is starting...")
print(f"Router 1 mac: {router1_mac}\nRouter 2 mac: {router2_mac}\n")

router1 = None
router2 = None

try:
    router1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    router2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    routers = [router1, router2]
except OSError as msg:
    router1 = None
    router2 = None
    print(msg)
try:
    router1.bind((HOST, R1_PORT))  # R1
    router2.bind((HOST, R2_PORT))  # R2
    print("[LISTENING]")
    for router in routers:
        thread = threading.Thread(target=start_listening, args=(router,), daemon=True)
        thread.start()
    online = True
    while online:
        answer = input("\nDo you want to terminate router? ")
        if answer == "y":
            online = False
            for router in routers:
                router.close()
            print("Terminating router")

except OSError as msg:
    router1.close()
    router1 = None
    router2.close()
    router2 = None
    print(msg)

if router1 is None or router2 is None:
    print("could not open socket")
    sys.exit(1)
