import socket
import sys
import time
import threading
from utility import (
    HOST,
    broadcast_data,
    connect_to_router,
    arp_table_socket,
    handle_clients,
    connect_to_node,
    get_ip_address,
    arp_table_mac,
    ip_address_port_dict,
    arp_table_socket_client,
    generate_onion_path,
    generate_keys,
    prepare_onion_packet,
)

node_index = 2
node_ip = get_ip_address(node_index)
node_mac = arp_table_mac[node_ip]
PORT = ip_address_port_dict[node_ip]
NODE_SOCKET = None

ROUTER = None


def start_listening(socket_conn):
    print(f"listening on {socket_conn.getsockname()}\n")
    socket_conn.listen(1)
    node_indexes = [1, 2, 3, 4, 5]
    node_indexes.remove(node_index)
    while None in arp_table_socket.values():
        conn, addr = socket_conn.accept()

        for ip_address, client_socket in arp_table_socket.items():
            if client_socket is None:
                arp_table_socket[ip_address] = conn
                print(f"Node {node_indexes[0]} is online")
                node_indexes.remove(node_indexes[0])
                break

    print(arp_table_socket)
    handle_clients(node_ip, arp_table_socket, False)


try:
    NODE_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    NODE_SOCKET = None
    print(msg)
try:

    # set up server
    NODE_SOCKET.bind((HOST, PORT))
    arp_table_socket.pop(node_ip, None)
    arp_table_socket.pop("router", None)

    print("[LISTENING]")

    thread = threading.Thread(target=start_listening, args=(NODE_SOCKET,), daemon=True)
    thread.start()

    # connect to clients
    for ip_address, socket_connection in arp_table_socket_client.items():
        if ip_address == "router":
            ROUTER = connect_to_router()
            arp_table_socket_client["router"] = ROUTER
            # print(ROUTER)
        if ip_address != node_ip and ip_address != "router":
            NODE = connect_to_node(node_ip, ip_address)
            if not NODE:
                sys.exit(1)
            arp_table_socket_client[ip_address] = NODE
            print(f"[Connecting] {node_ip} is connected to {ip_address}")
    print(arp_table_socket_client)

    time.sleep(1)
    online = True
    while online:
        print(f"\n\t\tEnter 'q' anytime to terminate node {node_index} ")
        answer = input(
            """\n
                    ********************
                    
                    CLIENTS:

                    1a
                    3a
                    4a
                    5a

                    ********************

                    Choose a node to send to:
                    """
        )
        if answer == "q":
            online = False
            NODE_SOCKET.close()
            print(f"\nTerminating node {node_index}\n")
        elif answer == "" or answer not in arp_table_socket_client.keys():
            print("\nInvalid option. Please try again")
        else:
            dest_ip = answer
            message = input("\n Enter a message: ")
            time.sleep(0.5)
            print("\n Creating random path of onion nodes...")
            path = generate_onion_path(node_ip, dest_ip)
            time.sleep(0.5)
            print(
                "\n Onion path: Sender {my_ip} -> {onion1} -> {onion2} -> {onion3} -> Receiver {onion4}".format(
                    my_ip=node_ip,
                    onion1=path[0],
                    onion2=path[1],
                    onion3=path[2],
                    onion4=path[3],
                )
            )
            time.sleep(0.5)
            print("\n Creating keys ...")
            generate_keys(path)
            time.sleep(0.5)
            print("\n Preparing packet ...")
            encrypted_packet = prepare_onion_packet(path, message, dest_ip)
            print("\nEncrypted_packet\t", encrypted_packet)
            print("\nPacket length\t", len(encrypted_packet))
            next_node = path[0]
            packet_to_send = bytes(node_ip, "utf-8") + encrypted_packet
            broadcast_data(arp_table_socket_client, packet_to_send, node_ip)
            time.sleep(4)

except OSError as msg:
    NODE_SOCKET.close()
    # print(msg)
    NODE_SOCKET = None
if NODE_SOCKET is None:
    print("could not open socket")
    sys.exit(1)
