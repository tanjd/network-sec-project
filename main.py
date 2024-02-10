import os
import time

from node import Node
from router import Router


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
