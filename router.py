import socket
import threading
from typing import Dict
from xmlrpc.client import Boolean

from logger import Logger

DISCONNECT_MESSAGE = "DISCONNECT"


class Router:
    def __init__(self, mac: str, ip: str, host: str, port: int):
        self.mac = mac
        self.ip = ip
        self.host = host
        self.port = port
        self.ip_to_socket: Dict[str, socket.socket] = {}
        self.server_thread = threading.Thread(target=self.start_server)
        log_file = f"{mac}.log"
        self.logger = Logger("node", log_file)
        self.sock: socket.socket

    def start_server(self):
        try:
            self.logger.info(f"{self.mac} is starting server")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.host, self.port))
            self.sock.listen()
            while True:
                client_socket, client_addr = self.sock.accept()
                client_ip, client_port = client_addr
                self.logger.info(f"Accepted connection from {client_ip}:{client_port}")
                self.ip_to_socket["1A"] = client_socket
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()

                # self.logger.info(f"Active Connections: {threading.activeCount() - 1}")

        except Exception as e:
            self.logger.error(f"Error in starting server: {e}")
            if self.sock:
                self.sock.close()

    def handle_client(self, client_socket: socket.socket):
        try:
            self.send("1A", "You are now connected to the router\n")

            self.logger.info(f"[Ready to receive packets from {client_socket.getpeername()}]\n")

            connected = True
            while connected:
                data = client_socket.recv(1024)
                if not data:
                    connected = False

                self.logger.info(f"Received {data!r}")

                message = data.decode("utf-8")
                if disconnect(message):
                    self.logger.info(f"{client_socket.getpeername()} has disconnected\n")
                    connected = False

        except Exception as e:
            self.logger.error(f"Error in handling client: {e}")
        finally:
            if client_socket:
                client_socket.close()

    def send(self, target: str, message: str):
        try:
            client_socket = self.ip_to_socket.get(target)
            if client_socket:
                client_socket.sendall(message.encode())
            else:
                self.logger.error(f"Client with IP {target} not found.")
        except Exception as e:
            self.logger.error(f"Error in sending data: {e}")

    def start(self):
        self.server_thread.start()


def disconnect(message: str) -> Boolean:
    return message == DISCONNECT_MESSAGE
