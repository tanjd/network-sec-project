import socket
import time
import threading
from Packet import Packet

router1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router1.bind(("localhost", 8100))  # R1

router2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router2.bind(("localhost", 8200))  # R2

routers = [router1, router2]
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

arp_table_socket = {node1_ip: node1, node2_ip: node2, node3_ip: node3}


def handle_client(ip, conn):
    print(f"\n[NEW CONNECTION] {ip} - {conn} connected.")
    print("[Receiving]\n")
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
            else:
                source_mac = router1_mac

            packet_header = received_packet.create_forward_packet(
                source_mac, arp_table_mac[received_packet.destination_ip]
            )
            router.send(bytes(packet_header, "utf-8"))
    conn.close()


def start_listening(router):
    print(f"listening on {router.getsockname()}\n")
    router.listen()
    global arp_table_socket
    global node1
    global node2
    global node3

    while node1 is None or node2 is None or node3 is None:
        conn, addr = router.accept()
        if node1 is None:
            node1 = conn
            print("Node 1 is online")
        elif node2 is None:
            node2 = conn
            print("Node 2 is online")
        elif node3 is None:
            node3 = conn
            print("Node 3 is online")
    arp_table_socket = {node1_ip: node1, node2_ip: node2, node3_ip: node3}
    # print(arp_table_socket)

    for ip, conn in arp_table_socket.items():
        thread = threading.Thread(target=handle_client, args=(ip, conn))
        thread.start()


print("[STARTING] router is starting...")
print(f"Router 1 mac: {router1_mac}\nRouter 2 mac: {router2_mac}\n")

print("[LISTENING]")
for router in routers:
    thread = threading.Thread(target=start_listening, args=(router,))
    thread.start()
