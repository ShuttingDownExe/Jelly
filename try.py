from scapy.layers.inet import TCP
from scapy.sendrecv import sniff


def isBadPkt(pkt):
    bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
    return bad


def check(pkt):
    if TCP in pkt and isBadPkt(pkt):
        print(len(pkt[TCP].payload))


if __name__ == '__main__':
    sniff(prn=check)
