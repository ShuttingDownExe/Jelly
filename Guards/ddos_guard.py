from collections import Counter

from scapy.layers.inet import TCP


def isBadPkt(pkt):
    bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
    return bad

def flood_guard(pkt):
    count = Counter()