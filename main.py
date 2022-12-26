#! /usr/bin/python3

from scapy.all import *

import Helpers.parallel_helper as ph
from Helpers import blocklist_helper as bh

from Guards.ddos_guard import count_packet
if __name__ == '__main__':
    bh.get_blocklist()

    count_packet()

    sniff(prn=ph.chain)
