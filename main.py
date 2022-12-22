#! /usr/bin/python3

from scapy.all import *

import Helpers.parallel_helper as ph
from Guards import ddos_guard
from Helpers import blocklist_helper as bh

if __name__ == '__main__':
    bh.get_blocklist()

    ddos_guard.count_packet()

    sniff(prn=ph.chain)
    #sniff(prn=snh.sniffer_func)
