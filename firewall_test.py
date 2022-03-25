from Packet import Packet

node_ip = "1a"
node_mac = "N1"

router_mac = "R1"


source_ip = node_ip
destination_ip = "2a"
payload = "MY DATA"
ip_data_length = len(payload)
protocol = 0
source_mac = node_mac
destination_mac = router_mac


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

test_count = 0


def test_firewall(firewall_rules, expected):
    global test_count
    test_count = test_count + 1
    print(
        "Test "
        + str(test_count)
        + ": "
        + str(packet.check_validity(firewall_rules) is expected)
    )


print("\n")

firewall_rules = {"A": ["ALL"], "D": []}
test_firewall(firewall_rules, True)

firewall_rules = {"A": [node_ip], "D": []}
test_firewall(firewall_rules, True)

firewall_rules = {"A": [node_ip, "ALL"], "D": []}
test_firewall(firewall_rules, True)

firewall_rules = {"A": [], "D": ["ALL"]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": [node_ip], "D": ["ALL"]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": ["ALL"], "D": ["ALL"]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": ["ALL"], "D": [node_ip]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": [], "D": [node_ip]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": [node_ip], "D": [node_ip]}
test_firewall(firewall_rules, False)

firewall_rules = {"A": [], "D": []}
test_firewall(firewall_rules, False)
