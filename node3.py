import socket
import time
from Packet import Packet
import threading


node_ip = "0x3A"
node_mac = "N3"
router = ("localhost", 8200)
node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)

print("[STARTING] node 3 is starting...")
node.connect(router)
print("[LISTENING] Node 3 is connected to router")
