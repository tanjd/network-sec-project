from platform import node
from utility import (
    add_firewall_rule,
    configure_firewall,
    display_firewall_rules,
    remove_firewall_rule,
)

# test = {'r1': {'0x1A':  socket.socket fd = 652, family = AddressFamily.AF_INET, type = SocketKind.SOCK_STREAM, proto = 0, laddr = ('127.0.0.1', 8100), raddr = ('127.0.0.1', 4774) > }, 'r2': {'0x2A': < socket.socket fd = 520, family = AddressFamily.AF_INET, type = SocketKind.SOCK_STREAM, proto = 0, laddr = ('127.0.0.1', 8200), raddr = ('127.0.0.1', 4777) > , '0x3A': < socket.socket fd = 644, family = AddressFamily.AF_INET, type = SocketKind.SOCK_STREAM, proto = 0, laddr = ('127.0.0.1', 8200), raddr = ('127.0.0.1', 4778)  }}
node_ip = "1a"
firewall_rules = {"A": ["2a"], "D": ["ALL", "1a"]}

# display_firewall_rules(node_ip, firewall_rules)
firewall_rules = configure_firewall(node_ip, firewall_rules)
