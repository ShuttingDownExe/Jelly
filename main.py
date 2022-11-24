#! /usr/bin/python3

from scapy.all import *

import Helpers.parallel_helper as ph


if __name__ == '__main__':
    sniff(prn=ph.chain)
