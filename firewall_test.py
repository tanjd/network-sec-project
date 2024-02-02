from Packet import Packet
from utility import add_firewall_rule, remove_firewall_rule

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
    print("Test " + str(test_count) + ": " + str(packet.check_validity(firewall_rules) is expected))


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

test_count2 = 0

print("\n")


def test_add_rule(firewall_rules, allow_or_deny, ip_address, expected):
    global test_count2
    test_count2 = test_count2 + 1
    firewall_rules = add_firewall_rule(allow_or_deny, ip_address, firewall_rules)
    print(f'Test add rule {test_count2}: { "True" if firewall_rules == expected else "False"}')


firewall_rules = {"A": [], "D": []}
expected = {"A": ["ALL"], "D": []}
test_add_rule(firewall_rules, "A", "ALL", expected)

firewall_rules = {"A": ["ALL"], "D": []}
expected = {"A": ["ALL"], "D": []}
test_add_rule(firewall_rules, "A", "ALL", expected)

firewall_rules = {"A": ["ALL"], "D": []}
expected = {"A": ["ALL"], "D": []}
test_add_rule(firewall_rules, "A", "All", expected)

firewall_rules = {"A": [], "D": []}
expected = {"A": ["ALL"], "D": []}
test_add_rule(firewall_rules, "A", "All", expected)

firewall_rules = {"A": [], "D": []}
expected = {"A": ["ALL"], "D": []}
test_add_rule(firewall_rules, "a", "All", expected)

firewall_rules = {"A": [], "D": []}
expected = {"A": [], "D": ["ALL"]}
test_add_rule(firewall_rules, "D", "All", expected)

firewall_rules = {"A": ["ALL"], "D": []}
expected = {"A": ["ALL", "1a"], "D": []}
test_add_rule(firewall_rules, "A", "1a", expected)

firewall_rules = {"A": ["ALL", "1a"], "D": []}
expected = {"A": ["ALL", "1a"], "D": []}
test_add_rule(firewall_rules, "A", "1a", expected)

test_count3 = 0

print("\n")


def test_remove_rule(firewall_rules, allow_or_deny, ip_address, expected):
    global test_count3
    test_count3 = test_count3 + 1
    firewall_rules = remove_firewall_rule(allow_or_deny, ip_address, firewall_rules)

    print(f'Test remove rule {test_count3}: { "True" if firewall_rules == expected else "False"}')


firewall_rules = {"A": ["ALL", "1a"], "D": []}
expected = {"A": ["ALL"], "D": []}
test_remove_rule(firewall_rules, "A", "1a", expected)

firewall_rules = {"A": ["ALL", "1a"], "D": []}
expected = {"A": ["ALL"], "D": []}
test_remove_rule(firewall_rules, "A", "1a", expected)

firewall_rules = {"A": ["ALL"], "D": []}
expected = {"A": [], "D": []}
test_remove_rule(firewall_rules, "A", "ALL", expected)

firewall_rules = {"A": ["ALL"], "D": []}
expected = {"A": [], "D": []}
test_remove_rule(firewall_rules, "A", "all", expected)

firewall_rules = {"A": [], "D": ["ALL"]}
expected = {"A": [], "D": []}
test_remove_rule(firewall_rules, "d", "all", expected)

firewall_rules = {"A": [], "D": ["1a"]}
expected = {"A": [], "D": []}
test_remove_rule(firewall_rules, "d", "1a", expected)

firewall_rules = {"A": [], "D": ["ALL"]}
expected = {"A": [], "D": ["ALL"]}
test_remove_rule(firewall_rules, "d", "1a", expected)
