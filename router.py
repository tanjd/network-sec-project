import socket
import time
import threading
from Packet import Packet

router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.bind(("localhost", 8100))  # R1

router_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_send.bind(("localhost", 8200))  # R2

router1_mac = "R1"
router2_mac = "R2"
server = ("localhost", 8000)

node1_ip = "0x1A"
node1_mac = "N1"
node2_ip = "0x2A"
node2_mac = "N2"

node2 = None

arp_table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
}


def handle_server():
    router.connect(server)
    print("[LISTENING] Node 2 is connected to node 1")
    arp_table_socket = {node2_ip: node2}
    print(arp_table_socket)
    while True:
        received_message = router.recv(1024)
        received_packet_header = received_message.decode("utf-8")
        if received_packet_header != "":

            received_packet = Packet(received_packet_header)

            print("\nThe packed received:")
            received_packet.print_packet_information()

            # find router_mac
            if received_packet.destination_mac == router1_mac:
                router_mac = router2_mac
            else:
                router_mac = router1_mac

            packet_header = received_packet.create_forward_packet(
                router_mac, arp_table_mac[received_packet.destination_ip]
            )

            destination_socket = arp_table_socket[received_packet.destination_ip]
            destination_socket.send(bytes(packet_header, "utf-8"))

            time.sleep(2)


def send_to_server(packet_header):
    router.send(bytes(packet_header, "utf-8"))


def handle_client(conn, addr):
    global node2
    print(f"[NEW CONNECTION] {addr} connected.")
    while node2 is None:
        node2 = conn
        print("node 2 is online")
    connected = True
    while connected:
        received_message = conn.recv(1024)
        received_packet_header = received_message.decode("utf-8")
        if received_packet_header:
            received_packet = Packet(received_packet_header)
            print("\nThe packed received:")
            received_packet.print_packet_information()

            packet_header = received_packet.create_forward_packet(
                router1_mac, arp_table_mac[received_packet.destination_ip]
            )
            router.send(bytes(packet_header, "utf-8"))
    conn.close()


def start():
    router_send.listen()
    print("[LISTENING] r2 is listening")

    while (threading.activeCount() - 1) < 1:
        conn, addr = router_send.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

    thread = threading.Thread(target=handle_server)
    thread.start()
    print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] router is starting...")
start()
