from pyrad.packet import Packet
from pyrad.dictionary import Dictionary

from scapy.all import rdpcap, Radius, IP, PcapReader
from scapy.layers.radius import _packet_codes as PACKET_TYPE
from scapy.layers.radius import _radius_attribute_types as ATTRIBUTE_TYPES
from scapy.layers.radius import _radius_attrs_values as ATTRIBUTE_VALUES

from vendor_attributes import VENDOR_ATTRIBUTES as VENDOR_ATTRIBUTES

from pprint import pprint as pp

import csv

_CONVERT = [
    "Event-Timestamp",
    "Acct-Terminate-Cause",
    "Aruba-User-Vlan",
    "Acct-Status-Type",
]

_TRANSFORM = {
    "Acct-Terminate-Cause": {
        1: "User Request",
        2: "Lost Carrier",
        3: "Lost Service",
        4: "Idle Timeout",
        5: "Session Timeout",
        6: "Admin Reset",
        7: "Admin Reboot",
        8: "Port Error",
        9: "NAS Error",
        10: "NAS Request",
        11: "NAS Reboot",
        12: "Port Unneeded",
        13: "Port Preempted",
        14: "Port Suspended",
        15: "Service Unavailable",
        16: "Callback ",
        17: "User Error",
        18: "Host Request",
    },
    "Acct-Status-Type": {
        1: "Start",
        2: "Stop",
        3: "Interim-Update",
        7: "Accounting-On",
        8: "Accounting-Off",
    },
}


def counter(field, packets):
    values = {}
    for i in packets:
        try:
            if i[field] not in values.keys():
                values[i[field]] = 0
            values[i[field]] += 1
        except Exception:
            continue
    return values


def transform(key, value):
    if key in _TRANSFORM.keys():
        value = _TRANSFORM[key][value]
    if type(value) is bytes:
        value = value.decode("utf-8")
    return value


def get_attribute_name(attribute):
    try:
        if attribute.type == 26:
            return VENDOR_ATTRIBUTES[attribute.vendor_id][attribute.vendor_type]
        else:
            return ATTRIBUTE_TYPES[attribute.type]
    except Exception:
        return "Unknown[{}][{}]".format(attribute.vendor_id, attribute.vendor_type)


packets = []
for i in PcapReader("/home/charlesr/tmp/hnt3.20191016.accounting/filter.pcap"):
    packet = {}
    packet["src_ip"] = i[IP].src
    packet["dst_ip"] = i[IP].dst
    if packet["src_ip"] == "130.91.210.162" or packet["dst_ip"] == "130.91.210.162":
        continue
    try:
        packet["type"] = PACKET_TYPE[i[Radius].code]
    except Exception:
        continue
    if packet["type"] == "Accounting-Response":
        continue
    for attribute in i[Radius].attributes:
        key = get_attribute_name(attribute)
        if type(attribute.value) is bytes and "x" in str(attribute.value):
            packet[key] = attribute.value.hex()
            if key in _CONVERT:
                packet[key] = int(packet[key], 16)
        else:
            packet[key] = attribute.value
        packet[key] = transform(key, packet[key])

    packets.append(packet)

hashed_packets = []
for i in packets:
    try:
        if "Acct-Status-Type" in i.keys():
            if str(i["Acct-Status-Type"]) in ["Start", "Stop"]:
                hashed_packets.append(
                    (
                        str(i["Acct-Session-Id"]),
                        str(i["User-Name"]),
                        str(i["Acct-Status-Type"]),
                    )
                )
    except Exception as e:
        print(e)
        continue

output = open("packets-full", "w")

for i in packets:
    output.write("" + str(i) + "\n")

output = open("packets", "w")

for i in hashed_packets:
    output.write("" + str(i) + "\n")

reader = csv.DictReader(open("cppm.csv"))
cppm = [dict(x) for x in reader]
hashed_cppm = []
for i in cppm:
    try:
        hashed_cppm.append(
            (str(i["acct_session_id"]), str(i["user_name"]), str(i["acct_status_type"]))
        )
    except Exception:
        print("FAILED: {}".format(i))

output = open("cppm", "w")

for i in hashed_cppm:
    output.write("" + str(i) + "\n")

i = []
o = []
print(hashed_packets[1])
print(hashed_cppm[1])

for entry in hashed_cppm:
    if entry in hashed_packets:
        i.append(entry)
    else:
        o.append(entry)

print("Number of CPPM in Packets: " + str(len(i)))
print("Number of CPPM not in Packets: " + str(len(o)))

i = []
o = []

for entry in hashed_packets:
    if entry in hashed_cppm:
        i.append(entry)
    else:
        o.append(entry)

print("Number of Packets in CPPM: " + str(len(i)))
print("Number of Packets not in CPPM: " + str(len(o)))
print(o[1:10])
