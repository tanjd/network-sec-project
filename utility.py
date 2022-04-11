import logging
import re
from Packet import Packet


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

    actions = """\n**************************************

    ACTIONS:

    [1] Ping sender [protocol 0]
    [2] Send message for recipient to log [protocol 1]
    [3] Disconnect recipient [protocol 2]
    [4] IP Spoofing [For Node 2]
    [5] Start/Stop Sniffing Attack [For Node 2]
    [6] Configure Firewall
    [7] Open Cat [TBC]
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
                response = input("Invalid action. Please enter a number between 1-6: ")
            else:
                valid = True
    return protocol


def broadcast_data(
    arp_table_socket,
    source_ip,
    destination_ip,
    source_mac,
    destination_mac,
    protocol,
    payload,
):
    for socket_conn in arp_table_socket.values():
        send_data(
            socket_conn,
            source_ip,
            destination_ip,
            source_mac,
            destination_mac,
            protocol,
            payload,
        )


def send_data(
    node, source_ip, destination_ip, source_mac, destination_mac, protocol, payload
):
    ip_data_length = len(payload)

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

    packet.print_packet_information()
    packet_header = packet.create_packet_header()
    try:
        node.sendall(packet_header)
        return True
    except:
        raise ConnectionError


def retrieve_packet(node):
    try:
        received_packet = node.recv(1024)
        if received_packet:
            received_packet = Packet(received_packet)
            print("\nThe packet received:")
            received_packet.print_packet_information()
            return received_packet
        return False
    except:
        return False


def get_file_name(node_ip):
    if node_ip == "1a":
        return "node1.log"
    elif node_ip == "2a":
        return "node2.log"
    elif node_ip == "3a":
        return "node3.log"


def display_firewall_rules(firewall_rules):
    print("\nCurrent firewall rules: ")
    print("\tEntry\tIP Address\tAction")
    entry = 1
    for allow_or_deny, ip_addesses in firewall_rules.items():
        for ip_address in ip_addesses:
            print(
                f"\t{entry}\t{ip_address}\t\t{'ALLOW' if allow_or_deny == 'A' else 'DENY'}"
            )
            entry += 1


def remove_firewall_rule_by_entry(entry, firewall_rules):
    index = 1
    for allow_or_deny, ip_addesses in firewall_rules.items():
        for ip_address in ip_addesses:
            if int(entry) == index:
                firewall_rules = remove_firewall_rule(
                    allow_or_deny, ip_address, firewall_rules
                )
                return firewall_rules
            index += 1
    return firewall_rules


def add_firewall_rule(allow_or_deny, ip_address, firewall_rules):
    allow_or_deny = allow_or_deny.upper()
    if (
        ip_address.upper() in firewall_rules[allow_or_deny]
        or ip_address.lower() in firewall_rules[allow_or_deny]
    ):
        return firewall_rules

    if ip_address.upper() == "ALL":
        firewall_rules[allow_or_deny].append(ip_address.upper())
        return firewall_rules

    firewall_rules[allow_or_deny].append(ip_address.lower())
    return firewall_rules


def remove_firewall_rule(allow_or_deny, ip_address, firewall_rules):
    allow_or_deny = allow_or_deny.upper()

    if ip_address.upper() in firewall_rules[allow_or_deny]:
        firewall_rules[allow_or_deny].remove(ip_address.upper())
        return firewall_rules

    if ip_address.lower() in firewall_rules[allow_or_deny]:
        firewall_rules[allow_or_deny].remove(ip_address.lower())
        return firewall_rules
    return firewall_rules


def configure_firewall(firewall_rules):
    display_firewall_rules(firewall_rules)
    configure = True
    while configure:
        action = input("\nEnter [1] to add a rule and [2] to delete existing rule: ")

        if action == "1":
            ip_address = input("Enter Source IP Address: ")
            allow_or_deny = input(f"Allow [A] or Deny [D] {ip_address} ?")
            firewall_rules = add_firewall_rule(
                allow_or_deny, ip_address, firewall_rules
            )
        else:
            entry = input("Enter entry to remove: ")
            firewall_rules = remove_firewall_rule_by_entry(entry, firewall_rules)

        display_firewall_rules(firewall_rules)

        x = input("Would you like to configure another firewall rule? (y/n) ")
        if x == "n":
            configure = False

    return firewall_rules


sniffing_mode = None
global_sniffing_ip = None
global_sniffing_mac = None


def set_sniffing_configuration(sniffing_ip, sniffing_mac):
    global sniffing_mode
    global global_sniffing_ip
    global global_sniffing_mac

    sniffing_mode = True
    global_sniffing_ip = sniffing_ip
    global_sniffing_mac = sniffing_mac


def set_sniffing_to_off(original_ip, original_mac):
    global sniffing_mode
    global global_sniffing_ip
    global global_sniffing_mac

    sniffing_mode = False
    global_sniffing_ip = original_ip
    global_sniffing_mac = original_mac


def start_receiver(
    arp_table_socket, conn, node_ip, node_mac, online, firewall_rules=None
):
    global sniffing_mode
    global global_sniffing_ip
    global global_sniffing_mac
    print(f"[Receiving] {node_ip}-{node_mac} is receiving from {conn}")
    connected = True

    while connected:

        received_packet = retrieve_packet(conn)
        if sniffing_mode:
            print("Sniffing mode activated")
            node_ip = global_sniffing_ip
            node_mac = global_sniffing_mac
        elif sniffing_mode is False:
            print("Sniffing mode deactivated")
            node_ip = global_sniffing_ip
            node_mac = global_sniffing_mac

        if received_packet is False:
            print(f"{node_ip} - {conn} disconnected")
            connected = False
            conn.close()
            break

        if (
            received_packet
            and not sniffing_mode
            and received_packet.print_packet_integrity_status(node_mac, node_ip)
        ):
            is_packet_valid = True
            if firewall_rules:
                print(f"\n[Checking] firewall rules {firewall_rules}")

                is_packet_valid = received_packet.check_validity(firewall_rules)
                print(
                    f"\n[Checking] Packet is {'allowed' if is_packet_valid else 'denied'}"
                )
            if is_packet_valid:
                connected = manage_protocol(
                    arp_table_socket, received_packet, node_ip, node_mac, online
                )
        elif sniffing_mode:
            if (
                received_packet.source_ip.hex() == node_ip
                and received_packet.source_mac.decode("utf-8") == node_mac
            ) or received_packet.print_packet_integrity_status(node_mac, node_ip):
                log_sniffed_packet(received_packet)
        else:
            print("[Checking] Packet Dropped")


def manage_protocol(arp_table_socket, received_packet, node_ip, node_mac, online):
    protocol = int.from_bytes(received_packet.protocol, byteorder="big")
    if protocol == 0:
        broadcast_data(
            arp_table_socket,
            node_ip,
            received_packet.source_ip.hex(),
            node_mac,
            received_packet.source_mac.decode("utf-8"),
            6,
            received_packet.payload.decode("utf-8"),
        )

        print(f"\n[PING] REPLYING TO {received_packet.source_ip.hex()} ...\n")
        return True
    elif protocol == 1:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s :: %(message)s",
            filename=get_file_name(received_packet.destination_ip.hex()),
        )

        logging.info(
            received_packet.source_ip.hex()
            + " - "
            + received_packet.destination_ip.hex()
            + " - "
            + received_packet.payload.decode("utf-8")
        )

        print("\n[LOG] data logged successfully.")
        return True

    elif protocol == 2:
        print(f"\n[CONNECTION CLOSED] {node_ip} disconnected.")
        for socket_conn in arp_table_socket.values():
            socket_conn.close()
        online.value = 0
        return False
    else:
        print(f"\n[PING] ... REPLY FROM {received_packet.source_ip.hex()} RECEIVED ")

        return True


def log_sniffed_packet(received_packet):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s :: %(message)s",
        filename="sniffing.log",
    )

    logging.info(
        received_packet.source_ip.hex()
        + " - "
        + received_packet.destination_ip.hex()
        + " - "
        + received_packet.payload.decode("utf-8")
    )
    print("\n[SNIFF PACKET] packet is logged.")
