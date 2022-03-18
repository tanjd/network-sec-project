import socket
import threading
from Packet import Packet
from utility import print_node_information, start_client_response, start_protocol

node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
node.bind(("localhost", 8000))
# node.listen(2)
node_ip = "0x1A"
node_mac = "N1"
router_mac = "R1"


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        received_message = conn.recv(1024)
        received_packet_header = received_message.decode("utf-8")
        if received_packet_header:
            received_packet = Packet(received_packet_header)
            print("\nRECEIVED PACKET .... ")
            received_packet.print_packet_information()
            received_packet.print_packet_integrity_status(node_mac, node_ip)

            protocol = start_client_response()
            start_protocol(protocol, received_packet, conn)

    conn.close()


def start():
    node.listen()
    print("\n[LISTENING] Node 1 is listening")
    while True:
        router_connection, address = node.accept()

        # doesn't start until connected to router
        if router_connection is not None:
            # print("\n" + str(router_connection) + "\n")
            break

    thread = threading.Thread(target=handle_client, args=(router_connection, address))
    thread.start()
    print(f"\n[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

    # IP Packet
    source_ip = node_ip
    destination_ip = "0x2A"
    payload = "MY DATA"
    ip_data_length = str(len(payload))
    protocol = "0"

    # Ethernet Fame
    source_mac = node_mac
    destination_mac = router_mac
    ip_packet = source_ip + destination_ip + ip_data_length + protocol + payload
    ethernet_data_length = str(len(ip_packet))

    packet = Packet(
        source_mac,
        destination_mac,
        ethernet_data_length,
        source_ip,
        destination_ip,
        protocol,
        ip_data_length,
        payload,
    )
    packet.print_packet_information()
    packet_header = packet.create_packet_header()
    answer = input("\nDo you want to send data (y|n): ")
    if answer == "y":
        router_connection.send(bytes(packet_header, "utf-8"))


print("********************************\n[STARTING] node 1 is starting...")
print_node_information(node_ip, node_mac)
start()
