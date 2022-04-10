import socket
import sys
import time
import threading
from utility import HOST, R1_PORT, connect_to_router

ROUTER = None

ROUTER = connect_to_router()
print(ROUTER)