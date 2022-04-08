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
        try:
            received_packet = conn.recv(1024)
            if received_packet:
                print("\nThe packet received:")

                received_packet = Packet(received_packet)
                received_packet.print_packet_information()

                for router_mac, arp_records in arp_table_mac.items():
                    if received_packet.destination_ip.hex() in arp_records.keys():
                        source_mac = router_mac
                        break

                if received_packet.destination_mac.decode("utf-8") != source_mac:
                    sending_connections = arp_table_socket[source_mac].values()

                    received_packet.create_forward_packet(
                        source_mac,
                        arp_table_mac[source_mac][received_packet.destination_ip.hex()],
                    )

                    for sending_conn in sending_connections:
                        try:
                            packet_header = received_packet.create_packet_header()
                            sending_conn.sendall(packet_header)
                        except ConnectionResetError:
                            print(
                                f"\n {received_packet.destination_ip.hex()} is not online."
                            )
                            connected = False
        except:
            for socket_connections in arp_table_socket.values():
                for ip, node_conn in socket_connections.items():
                    if node_conn == conn:
                        socket_connections[ip] = None
            connected = False

    conn.close()


def handle_clients(arp_table_socket):
    for ip, conn in arp_table_socket.items():
        thread = threading.Thread(target=handle_client, args=(ip, conn))
        thread.start()


def start_listening(router):
    global arp_table_socket
    socket_port = router.getsockname()[1]

    print(f"listening on {router.getsockname()}\n")
    router.listen()

    while arp_table_socket[router1_mac][node1_ip] is None and socket_port == R1_PORT:
        conn, addr = router.accept()
        if arp_table_socket[router1_mac][node1_ip] is None:
            arp_table_socket[router1_mac][node1_ip] = conn
            print("Node 1 is online")

    while (
        arp_table_socket[router2_mac][node2_ip] is None
        or arp_table_socket[router2_mac][node3_ip] is None
    ) and socket_port == R2_PORT:
        conn, addr = router.accept()

        if arp_table_socket[router2_mac][node2_ip] is None:
            arp_table_socket[router2_mac][node2_ip] = conn
            print("Node 2 is online")

        elif arp_table_socket[router2_mac][node3_ip] is None:
            arp_table_socket[router2_mac][node3_ip] = conn
            print("Node 3 is online")

    if socket_port == R1_PORT:
        router_key = router1_mac
    else:
        router_key = router2_mac
    handle_clients(arp_table_socket[router_key])


HOST = "localhost"

R1_PORT = 8100
R2_PORT = 8200

router1_mac = "R1"
router2_mac = "R2"

node1_ip = "1a"
node1_mac = "N1"

node2_ip = "2a"
node2_mac = "N2"

node3_ip = "3a"
node3_mac = "N3"

arp_table_mac = {
    router1_mac: {node1_ip: node1_mac},
    router2_mac: {node2_ip: node2_mac, node3_ip: node3_mac},
}

node1 = None
node2 = None
node3 = None

arp_table_socket = {
    router1_mac: {node1_ip: node1},
    router2_mac: {node2_ip: node2, node3_ip: node3},
}

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
    router1.bind((HOST, R1_PORT))
    router2.bind((HOST, R2_PORT))

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
