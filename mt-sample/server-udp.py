import socket
import threading

HEADER = 60  ##20 bytes for header, 1 byte of data (min)
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
print(type(SERVER))
ADDR = ("localhost", PORT)
FORMAT = "utf-8"
DISCONNECT_MESSAGE = "!DISCONNECT"

R1 = "0x11"
R2 = "0x21"
R1_ARP = {"N1": "0x1A"}
R2_ARP = {"N2": "0x2A"}, {"N3": "0x2B"}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            print(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False

            print(f"[{addr}] {msg}")
            conn.send("Msg received".encode(FORMAT))

    conn.close()


def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] server is starting...")
start()
