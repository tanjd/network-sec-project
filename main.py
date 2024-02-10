import logging
import os
import socket
import threading
import time
from typing import Dict, Tuple


def configure_logging(logger_name, log_file):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


class Router:
    def __init__(self, mac: str, ip: str, host: str, port: int):
        self.mac = mac
        self.ip = ip
        self.host = host
        self.port = port
        self.ip_to_socket: Dict[str, socket.socket] = {}
        self.server_thread = threading.Thread(target=self.start_server)
        self.logger = router_logger

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
        except Exception as e:
            self.logger.error(f"Error in starting server: {e}")
            if self.sock:
                self.sock.close()

    def handle_client(self, client_socket: socket.socket):
        try:
            self.logger.info(f"[Ready to receive packets from {client_socket.getpeername()}]\n")
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.logger.info(f"Received {data!r}")
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


class Node:
    def __init__(self, mac: str, ip: str, router_host: str, router_port: int):
        self.mac = mac
        self.ip = ip
        self.router_host = router_host
        self.router_port = router_port
        self.server_thread = threading.Thread(target=self.connect_to_router)
        self.logger = node_logger

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


if __name__ == "__main__":
    router_log_file = "router.log"
    node_log_file = "node.log"

    for log_file in [router_log_file, node_log_file]:
        if os.path.exists(log_file):
            os.remove(log_file)

    router_logger = configure_logging("router", router_log_file)
    node_logger = configure_logging("node", node_log_file)

    HOST = "127.0.0.1"
    PORT = 65431
    router = Router("R1", "1B", HOST, PORT)
    router.start()

    node = Node("N1", "1A", HOST, PORT)
    node.start()

    try:
        time.sleep(2.5)
        node.send("hello server")
        router.send("1A", "Hello client")
    finally:
        if router.sock:
            router.sock.close()
        if node.sock:
            node.sock.close()
