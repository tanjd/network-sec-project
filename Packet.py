class Packet:
    def __init__(self, *args):
        if len(args) > 1:
            self.source_mac = bytes(args[0], "utf-8")
            self.destination_mac = bytes(args[1], "utf-8")
            self.ethernet_data_length = args[2].to_bytes(1, byteorder="big")
            self.source_ip = bytes.fromhex(args[3])
            self.destination_ip = bytes.fromhex(args[4])
            self.protocol = args[5].to_bytes(1, byteorder="big")
            self.ip_data_length = args[6].to_bytes(1, byteorder="big")
            self.payload = bytes(args[7], "utf-8")
        else:
            received_packet = args[0]
            self.source_mac = received_packet[0:2]
            self.destination_mac = received_packet[2:4]
            self.ethernet_data_length = received_packet[4:5]
            self.source_ip = received_packet[5:6]
            self.destination_ip = received_packet[6:7]
            self.protocol = received_packet[7:8]
            self.ip_data_length = received_packet[8:9]
            self.payload = received_packet[9:]

    def create_packet_header(self):

        ethernet_header = (
            self.source_mac + self.destination_mac + self.ethernet_data_length
        )
        ip_header = self.source_ip + self.destination_ip
        return (
            ethernet_header
            + ip_header
            + self.protocol
            + self.ip_data_length
            + self.payload
        )

    def print_packet_information(self):
        print("\n********************************")
        # print(self.create_packet_header())
        print(
            "\nSource MAC address:      {source_mac}"
            "\nDestination MAC address: {destination_mac}"
            "\nEthernet Data Length:    {ethernet_data_length} bytes"
            "\nSource IP address:       {source_ip}"
            "\nDestination IP address:  {destination_ip}"
            "\nProtocol:                {protocol}"
            "\nIP Packet Data length:   {data_length} bytes"
            "\nPayload:                 {payload}".format(
                source_mac=self.source_mac.decode("utf-8"),
                destination_mac=self.destination_mac.decode("utf-8"),
                ethernet_data_length=int.from_bytes(
                    self.ethernet_data_length, byteorder="big"
                ),
                source_ip=self.source_ip.hex(),
                destination_ip=self.destination_ip.hex(),
                protocol=int.from_bytes(self.protocol, byteorder="big"),
                data_length=int.from_bytes(self.ip_data_length, byteorder="big"),
                payload=self.payload.decode("utf-8"),
            )
        )

    def create_forward_packet(self, source_mac, destination_mac):
        self.source_mac = bytes(source_mac, "utf-8")
        self.destination_mac = bytes(destination_mac, "utf-8")

    def print_packet_integrity_status(self, node_mac, node_ip):
        mac_check = bytes(node_mac, "utf-8") == self.destination_mac
        ip_check = bytes.fromhex(node_ip) == self.destination_ip
        print(
            "\nPacket integrity:"
            "\nDestination MAC address matches own MAC address: {mac}".format(
                mac=mac_check
            )
        )
        print(
            "\nDestination IP address matches own IP address: {ip}".format(ip=ip_check)
        )

        if mac_check and ip_check:
            return True
        return False

    def check_validity(self, firewall_rules):
        if "ALL" in firewall_rules["D"] or self.source_ip.hex() in firewall_rules["D"]:
            return False
        if "ALL" in firewall_rules["A"] or self.source_ip.hex() in firewall_rules["A"]:
            return True
        return False
