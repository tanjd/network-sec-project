# Source: https://stackoverflow.com/questions/41890570/python-hex-ip-as-string-to-ddn-ip-string
import ipaddress

# download pysnmp.hlapi: pip install pysnmp
from pysnmp.hlapi import OctetString

ip = OctetString(hexValue="0000001A")  # 0.0.0.26 = 00 00 00 1A
source_ip = ipaddress.IPv4Address(ip.asOctets())

print(source_ip)
# print(type(source_ip))
print(len(ip))
