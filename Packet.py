class Packet:
    def __init__(self, *args):
        if len(args) > 1:
            # (source_ip, destination_ip, source_mac, destination_mac, protocol, payload)
            self.source_ip = args[0]
            self.destination_ip = args[1]
            self.source_mac = args[2]
            self.destination_mac = args[3]
            self.protocol = args[4]
            self.data_length = len(args[5])
            self.payload = args[5]
        else:
            self.source_mac = args[0][0:2]
            self.destination_mac = args[0][2:4]
            self.source_ip = args[0][4:8]
            self.destination_ip = args[0][8:12]
            self.protocol = args[0][12:13]
            self.data_length = args[0][13:14]
            self.payload = args[0][14:]

    def create_packet_header(self):
        ethernet_header = self.source_mac + self.destination_mac
        ip_header = self.source_ip + self.destination_ip
        return (
            ethernet_header
            + ip_header
            + str(self.protocol)
            + str(self.data_length)
            + self.payload
        )

    def print_packet_information(self):
        print(
            "\nSource MAC address: {source_mac}"
            "\nDestination MAC address: {destination_mac}"
            "\nSource IP address: {source_ip}"
            "\nDestination IP address: {destination_ip}"
            "\nProtocol: {protocol}"
            "\nData length: {data_length}"
            "\nPayload: {payload}".format(
                source_mac=self.source_mac,
                destination_mac=self.destination_mac,
                source_ip=self.source_ip,
                destination_ip=self.destination_ip,
                protocol=self.protocol,
                data_length=self.data_length,
                payload=self.payload,
            )
        )

    def create_forward_packet(self, source_mac, destination_mac):
        ethernet_header = source_mac + destination_mac
        ip_header = self.source_ip + self.destination_ip
        return (
            ethernet_header
            + ip_header
            + str(self.protocol)
            + str(self.data_length)
            + self.payload
        )

    def print_packet_integrity_status(self, node_mac, node_ip):
        print(
            "\nPacket integrity:"
            "\ndestination MAC address matches own MAC address: {mac}".format(
                mac=(node_mac == self.destination_mac)
            )
        )
        print(
            "\ndestination IP address matches own IP address: {mac}".format(
                mac=(node_ip == self.destination_ip)
            )
        )
