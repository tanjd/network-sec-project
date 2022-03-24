class Packet:
    def __init__(self, *args):
        if len(args) > 1:
            # (source_mac, destination_mac, ethernet_data_length , source_ip, destination_ip, protocol , ip_data_length , payload)
            self.source_mac = args[0]
            self.destination_mac = args[1]
            self.ethernet_data_length = args[2]
            self.source_ip = args[3]
            self.destination_ip = args[4]
            self.protocol = args[5]
            self.ip_data_length = args[6]
            self.payload = args[7]

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
        print(
            "\n********************************"
            "\nSource MAC address:      {source_mac}"
            "\nDestination MAC address: {destination_mac}"
            "\nEthernet Data Length:    {ethernet_data_length} bytes"
            "\nSource IP address:       {source_ip}"
            "\nDestination IP address:  {destination_ip}"
            "\nProtocol:                {protocol}"
            "\nIP Packet Data length:   {data_length} bytes"
            "\nPayload:                 {payload}".format(
                source_mac=self.source_mac,
                destination_mac=self.destination_mac,
                ethernet_data_length=self.ethernet_data_length,
                source_ip=self.source_ip,
                destination_ip=self.destination_ip,
                protocol=self.protocol,
                data_length=self.ip_data_length,
                payload=self.payload,
            )
        )

    def create_forward_packet(self, source_mac, destination_mac):
        # ethernet_header = source_mac + destination_mac
        # ip_header = self.source_ip + self.destination_ip
        return Packet(
            source_mac,
            destination_mac,
            self.ethernet_data_length,
            self.source_ip,
            self.destination_ip,
            self.protocol,
            self.ip_data_length,
            self.payload,
        )

    def print_packet_integrity_status(self, node_mac, node_ip):
        print(
            "\nPacket integrity:"
            "\nDestination MAC address matches own MAC address: {mac}".format(
                mac=(node_mac == self.destination_mac)
            )
        )
        print(
            "\nDestination IP address matches own IP address: {mac}".format(
                mac=(node_ip == self.destination_ip)
            )
        )

    def check_validity(self, firewall_rules):
        if "ALL" in firewall_rules["D"] or self.source_ip in firewall_rules["D"]:
            return False
        if "ALL" in firewall_rules["A"] or self.source_ip in firewall_rules["A"]:
            return True
        return False

    def encode_packet(self):
        encoded_packet = (
            bytes(self.source_mac, "utf-8")
            + bytes(self.destination_mac, "utf-8")
            + self.ethernet_data_length.to_bytes(1, byteorder="big")
            + bytes.fromhex(self.source_ip)
            + bytes.fromhex(self.destination_ip)
            + self.protocol.to_bytes(1, byteorder="big")
            + self.ip_data_length.to_bytes(1, byteorder="big")
            + bytes(self.payload, "utf-8")
        )
        return encoded_packet
