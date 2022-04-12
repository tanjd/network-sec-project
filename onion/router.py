import socket
import sys
import time
import threading
from utility import HOST, R1_PORT, arp_table_socket, handle_clients


def start_listening(socket_conn):
    print(f"listening on {socket_conn.getsockname()}\n")
    socket_conn.listen(1)
    node_index = 1
    while None in arp_table_socket.values():
        conn, addr = socket_conn.accept()

        for ip_address, client_socket in arp_table_socket.items():
            if client_socket is None:
                arp_table_socket[ip_address] = conn
                print(f"Node {node_index} is online")
                node_index += 1
                break

    # print(arp_table_socket)
    handle_clients(None, arp_table_socket, True)


try:
    ROUTER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as msg:
    ROUTER_SOCKET = None
    print(msg)
try:
    ROUTER_SOCKET.bind((HOST, R1_PORT))
    arp_table_socket.pop("router", None)

    print("[LISTENING]")

    thread = threading.Thread(
        target=start_listening, args=(ROUTER_SOCKET,), daemon=True
    )
    thread.start()

    time.sleep(1)
    online = True
    while online:
        answer = input("\nDo you want to terminate router? ")
        if answer == "q":
            online = False
            ROUTER_SOCKET.close()
            print("Terminating router")

except OSError as msg:
    ROUTER_SOCKET.close()
    ROUTER_SOCKET = None
    print(msg)

if ROUTER_SOCKET is None:
    print("could not open socket")
    sys.exit(1)
