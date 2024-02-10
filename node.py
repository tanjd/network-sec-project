import socket
import threading

from logger import Logger


class Node:
    def __init__(self, mac: str, ip: str, router_host: str, router_port: int):
        self.mac = mac
        self.ip = ip
        self.router_host = router_host
        self.router_port = router_port
        self.server_thread = threading.Thread(target=self.connect_to_router)
        node_log_file = f"{mac}.log"
        self.logger = Logger("node", node_log_file)

    def connect_to_router(self):
        try:
            self.logger.info(f"{self.mac} is connecting to router at {self.router_host}:{self.router_port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.router_host, self.router_port))
            self.logger.info(f"{self.mac} is connected to router.")
            threading.Thread(target=self.handle_client, args=(self.sock,)).start()
        except Exception as e:
            self.logger.error(f"Error in connecting to router: {e}")
            if self.sock:
                self.sock.close()

    def send(self, message: str):
        try:
            self.sock.sendall(message.encode())
        except Exception as e:
            self.logger.error(f"Error in sending data: {e}")

    def handle_client(self, server_socket: socket.socket):
        try:
            self.logger.info(f"[Ready to receive packets from {server_socket.getpeername()}]\n")
            while True:
                data = server_socket.recv(1024)
                if not data:
                    break
                self.logger.info(f"Received {data!r}")
        except Exception as e:
            self.logger.error(f"Error in handling client: {e}")
        finally:
            if server_socket:
                server_socket.close()

    def start(self):
        self.server_thread.start()
