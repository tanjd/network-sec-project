import socket
import sys
import time
import threading
from utility import HOST, R1_PORT, connect_to_router

ROUTER = None

ROUTER = connect_to_router()
print(ROUTER)

# try:
#     ROUTER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# except OSError as msg:
#     ROUTER = None
#     print(msg)
# try:
#     ROUTER.connect(ROUTER_SOCKET)
# except OSError as msg:
#     ROUTER.close()
#     print(msg)
#     ROUTER = None
# if ROUTER is None:
#     print("could not open socket")
#     sys.exit(1)
