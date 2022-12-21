#! /usr/bin/python3

from scapy.all import *

import schedule

import Helpers.parallel_helper as ph
from Helpers import blocklist_helper as bh


from Guards import ddos_guard


if __name__ == '__main__':
    bh.get_blocklist()

    schedule.every().second.do(ddos_guard.dos_guard)

    sniff(prn=ph.chain)
    #sniff(prn=snh.sniffer_func)
