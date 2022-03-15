def create_packet(
    source_ip, destination_ip, source_mac, destination_mac, protocol, payload
):
    ip_header = source_ip + destination_ip
    ethernet_header = source_mac + destination_mac
    data_length = len(payload)
    packet = ethernet_header + ip_header + protocol + data_length + payload
    return packet


def get_source_mac(received_message):
    return received_message[0:2]


def get_destination_mac(received_message):
    return received_message[2:4]


def get_source_ip(received_message):
    return received_message[4:8]


def get_destination_ip(received_message):
    return received_message[8:12]


def get_protocol(received_message):
    return received_message[12:13]


def get_data_length(received_message):
    return received_message[13:14]


def get_payload(received_message):
    return received_message[14:]
