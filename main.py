#! /usr/bin/python3

from scapy.all import *

import Helpers.parallel_helper as ph
from Helpers.sniff_helper import sniffer_helper as snh


if __name__ == '__main__':
    sniff(prn=ph.chain)
    #sniff(prn=snh.sniffer_func)
