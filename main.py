import os
import time

from node import Node
from router import DISCONNECT_MESSAGE, Router


def remove_log_files():
    files = os.listdir()
    log_files = [file for file in files if file.endswith(".log")]

    for log_file in log_files:
        os.remove(log_file)


if __name__ == "__main__":
    remove_log_files()

    HOST = "127.0.0.1"
    PORT = 65431

    router = Router("R1", "1B", HOST, PORT)
    router.start()

    node1 = Node("N1", "1A", HOST, PORT)
    node1.start()

    # node2 = Node("N2", "2A", HOST, PORT)
    # node2.start()

    try:
        time.sleep(2.5)
        node1.send("hello server")
        router.send("1A", "Hello client")
        node1.send(DISCONNECT_MESSAGE)
    finally:
        if router.sock:
            router.sock.close()
        if node1.sock:
            node1.sock.close()
