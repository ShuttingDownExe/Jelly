import subprocess
from collections import Counter

import threading
import time
import schedule

from scapy.layers.inet import TCP, IP

from Helpers import sniffer_helper as snh

from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, FUNC, INFO
from Helpers import sniffer_helper as snh

count = Counter({})
ip_list = []
payload_lst = []


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

def timed_check():
    cease_continuous_run = threading.Event()
    class ScheduleThread(threading.Thread):
        @classmethod
        def run(cls):
            while not cease_continuous_run.is_set():
                schedule.run_pending()
                time.sleep(1)

    continuous_thread = ScheduleThread()
    continuous_thread.start()
    return cease_continuous_run