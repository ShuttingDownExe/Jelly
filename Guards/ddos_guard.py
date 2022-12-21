from collections import Counter

from scapy.layers.inet import TCP, IP

from Helpers.output_helper import print_output, WARN, FUNC, INFO


class ddos_guard:
    count = Counter({})
    ip_list = []
    payload_lst = []

    @staticmethod
    def isBadPkt(pkt):
        bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
        return bad

    @staticmethod
    def flood_guard(pkt):
        if IP in pkt and ddos_guard.isBadPkt(pkt):
            ddos_guard.payload_lst.append(len(pkt[TCP].payload))
            ddos_guard.ip_list.append(str(pkt[IP].src))

        ddos_guard.count.update(ddos_guard.payload_lst)

    @staticmethod
    def dos_guard():
        print("ddos guard")
        l = len(ddos_guard.ip_list)
        if l > 100:
            print_output(f"POSSIBLE DDOS ATTACK: Number of (Identified) bad pkts: {len(ddos_guard.ip_list)}", WARN)

        ddos_guard.ip_list = []
        ddos_guard.payload_list = []
