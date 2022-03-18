import socket
import time
from Packet import Packet
import threading

node_ip = "0x1A"
node_mac = "N1"
router = ("localhost", 8100)
node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)

print("[STARTING] node 1 is starting...")
node.connect(router)
print("[LISTENING] Node 1 is connected to router")
