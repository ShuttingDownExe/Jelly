import sched
import time
from collections import Counter

from scapy.layers.inet import TCP, IP

from Helpers.output_helper import print_output, WARN

count = Counter({})
ip_list = []
payload_lst = []

s = sched.scheduler(time.time, time.sleep)

def isBadPkt(pkt):
    bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
    return bad


def flood_guard(pkt):
    if IP in pkt and isBadPkt(pkt):
        payload_lst.append(len(pkt[TCP].payload))
        ip_list.append(str(pkt[IP].src))

    count.update(payload_lst)


def dos_guard():
    print("ddos guard")
    if snh.pkt_count > 100:
        print_output(f"POSSIBLE DDOS ATTACK: Number of (Identified) bad pkts: {len(ip_list)}", WARN)

    snh.pkt_count = 0
    s.enter(1, 1, dos_guard, ())