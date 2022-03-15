import socket
import time
from utility import create_packet

router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.bind(("localhost", 8100))

router_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_send.bind(("localhost", 8200))

router_mac = "R1"

server = ("localhost", 8000)

node1_ip = "0x1A"
node1_mac = "N1"
node2_ip = "0x2A"
node2_mac = "N2"

router_send.listen(4)
node1 = None
node2 = None

while node2 is None:
    client, address = router_send.accept()

    if node2 is None:
        node2 = client
        print("node 2 is online")

arp_table_socket = {node1_ip: node1, node2_ip: node2}
arp_table_mac = {
    node1_ip: node1_mac,
    node2_ip: node2_mac,
}
print(arp_table_mac)
router.connect(server)
while True:
    received_message = router.recv(1024)
    received_message = received_message.decode("utf-8")
    if received_message != "":
        source_mac = received_message[0:2]
        destination_mac = received_message[2:4]
        source_ip = received_message[4:8]
        destination_ip = received_message[8:12]
        protocol = received_message[12:13]
        data_length = received_message[13:14]
        payload = received_message[14:]

        print(
            "The packed received:\n Source MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(
                source_mac=source_mac, destination_mac=destination_mac
            )
        )
        print(
            "\nSource IP address: {source_ip}, Destination IP address: {destination_ip}".format(
                source_ip=source_ip, destination_ip=destination_ip
            )
        )
        print("\nprotocol: " + protocol)
        print("\ndata length: " + data_length)
        print("\naPayload: " + payload)

        ethernet_header = router_mac + arp_table_mac[destination_ip]
        IP_header = source_ip + destination_ip
        packet = ethernet_header + IP_header + payload
        packet = create_packet(
            source_ip, destination_ip, source_mac, destination_mac, protocol, payload
        )
        destination_socket = arp_table_socket[destination_ip]

        destination_socket.send(bytes(packet, "utf-8"))
        time.sleep(2)
