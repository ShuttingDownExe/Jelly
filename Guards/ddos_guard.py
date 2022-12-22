import sched
import time
from collections import Counter

from scapy.layers.inet import TCP, IP

from Helpers.output_helper import print_output, WARN

class ddos_guard:
    count = Counter({})
    ip_list = []
    payload_lst = []
    pkt_count = 0
    s = sched.scheduler(time.time, time.sleep)
def isBadPkt(pkt):
    bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
    return bad


def flood_guard(pkt):
    if IP in pkt and isBadPkt(pkt):
        ddos_guard.payload_lst.append(len(pkt[TCP].payload))
        ddos_guard.ip_list.append(str(pkt[IP].src))

    ddos_guard.count.update(ddos_guard.payload_lst)
    ddos_guard.pkt_count+=1


def count_packet():
    if ddos_guard.pkt_count > 100:
        print_output(f"POSSIBLE DDOS ATTACK: Number of (Identified) bad pkts: {len(ddos_guard.ip_list)}", WARN)

    ddos_guard.pkt_count = 0
    ddos_guard.s.enter(1, 1, count_packet, ())
    ddos_guard.s.run()