#! /usr/bin/python3

from scapy.all import *

import Helpers.parallel_helper as ph
from Helpers import blocklist_helper as bh

if __name__ == '__main__':
    bh.get_blocklist()


    sniff(prn=ph.chain)
    #sniff(prn=snh.sniffer_func)
