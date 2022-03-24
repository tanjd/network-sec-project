import logging
from Packet import Packet


def decode_packet(received_packet):
    if received_packet:
        source_mac = received_packet[0:2].decode("utf-8")
        destination_mac = received_packet[2:4].decode("utf-8")
        ethernet_data_length = int.from_bytes(received_packet[4:5], byteorder="big")
        source_ip = received_packet[5:6].hex()
        destination_ip = received_packet[6:7].hex()
        protocol = int.from_bytes(received_packet[7:8], byteorder="big")
        ip_data_length = int.from_bytes(received_packet[8:9], byteorder="big")
        payload = received_packet[9:].decode("utf-8")

        return Packet(
            source_mac,
            destination_mac,
            ethernet_data_length,
            source_ip,
            destination_ip,
            protocol,
            ip_data_length,
            payload,
        )
    return None


def print_node_information(node_ip, node_mac):
    print(
        "\n*******************************"
        "\nNode IP address:     {node_ip}"
        "\nNode MAC address:    {node_mac}".format(node_ip=node_ip, node_mac=node_mac)
    )


def choose_recipient():
    print(
        """\n*****************************
        CLIENTS:

        [1] Node 1
        [2] Node 2
        [3] Node 3
        
        """
    )
    addr = input("\n Enter number (1,2,3) of the receiving node: ")
    ip_dict = {"1": "1a", "2": "2a", "3": "3a"}
    return ip_dict[addr]


def choose_protocol():
    # E.G When Node 1 sends datagram to Node 2, start_client_response() allows Node 2 to select desired action (i.e. protocol). Returns protocol number.

    actions = """\n**************************************

    ACTIONS:

    [1] Ping sender [protocol 0]
    [2] Send message for recipient to log [protocol 1]
    [3] Disconnect recipient [protocol 2]
    [4] IP Spoofing [TBC]
    [5] Sniffing Attack [TBC]
    [6] Open Cat [TBC]
    """
    print(actions)
    response = input("Enter number (1,2,3,4,5,6) of the action you'd like to take: ")

    valid = False
    while not valid:
        if response == "":
            print(actions)
            response = input(
                "Enter number (1,2,3,4,5,6) of the action you'd like to take: "
            )
        else:
            protocol = int(response) - 1
            if protocol not in [0, 1, 2, 3, 4, 5]:
                response = input("Invalid action. Please enter a number between 1-5: ")
            else:
                valid = True
    return protocol


def send_data(node, node_ip, destination_ip, node_mac, router_mac, protocol, data):
    # IP Packet
    source_ip = node_ip
    destination_ip = destination_ip
    payload = data
    ip_data_length = len(payload)

    # Ethernet Fame
    source_mac = node_mac
    destination_mac = router_mac

    # Max Length of IP Payload: 251 (\xfb)
    # Max length of ethernet: 255 bytes (\xff)
    ethernet_data_length = (
        len(bytes.fromhex(source_ip))
        + len(bytes.fromhex(destination_ip))
        + len(str(protocol))
        + len(payload)
        + len(ip_data_length.to_bytes(1, byteorder="big"))
    )

    packet = Packet(
        source_mac,
        destination_mac,
        ethernet_data_length,
        source_ip,
        destination_ip,
        protocol,
        ip_data_length,
        payload,
    )
    encoded_packet = packet.encode_packet()
    packet.print_packet_information()
    # packet_header = packet.create_packet_header()
    node.send(encoded_packet)
    return True


def retrieve_packet(node, node_ip, node_mac):
    received_message = node.recv(1024)
    received_packet_header = decode_packet(received_message)
    if received_packet_header:
        received_packet = received_packet_header

        print("\nThe packet received:")
        received_packet.print_packet_information()
        received_packet.print_packet_integrity_status(node_mac, node_ip)
    return received_packet


def get_file_name(node_ip):
    if node_ip == "1a":
        return "node1.log"
    elif node_ip == "2a":
        return "node2.log"
    elif node_ip == "3a":
        return "node3.log"


def start_receiver(node, node_ip, node_mac, firewall_rules=None):
    print(f"[Receiving] {node_ip}-{node_mac} is connected to router")
    connected = True

    while connected:
        is_packet_valid = True

        received_packet = retrieve_packet(node, node_ip, node_mac)

        if firewall_rules:
            print(f"\n[Checking] firewall rules {firewall_rules}")

            is_packet_valid = received_packet.check_validity(firewall_rules)
            print(f"\n[Checking] Packet is {'valid' if is_packet_valid else 'invalid'}")

        if is_packet_valid:
            # PING
            if received_packet.protocol == 0:
                protocol = 6
                packet_to_send = Packet(
                    received_packet.destination_mac,
                    received_packet.source_mac,
                    received_packet.ethernet_data_length,
                    received_packet.destination_ip,
                    received_packet.source_ip,
                    protocol,
                    received_packet.ip_data_length,
                    received_packet.payload,
                )

                print(f"\n[PING] REPLYING TO {received_packet.source_ip} ...\n")
                # packet_to_send.print_packet_information()

                packet_header = packet_to_send.encode_packet()
                node.send(packet_header)

            # LOG
            elif received_packet.protocol == 1:
                # log message down

                # create logger
                # logging.basicConfig(level=logging.INFO, format='%(asctime)s :: %(message)s', filename='sample.log')
                logging.basicConfig(
                    level=logging.INFO,
                    format="%(asctime)s :: %(message)s",
                    filename=get_file_name(received_packet.destination_ip),
                )

                # logging.info(received_packet.payload)
                logging.info(
                    received_packet.source_ip
                    + " - "
                    + received_packet.destination_ip
                    + " - "
                    + received_packet.payload
                )

                print(f"\n[LOG] data logged successfully.")

            elif received_packet.protocol == 2:
                # terminate node/ disconnect from network
                print(f"\n[CONNECTION CLOSED] {node_ip} disconnected.")
                connected = False
                node.close()

            # SPOOFING
            elif received_packet.protocol == 3:
                pass

            # SNIFFING
            elif received_packet.protocol == 4:
                pass

            # OPEN CAT
            elif received_packet.protocol == 5:
                pass

            # PING REPLY
            else:
                print(f"\n[PING] ... REPLY FROM {received_packet.source_ip} RECEIVED ")
