#! /usr/bin/python3

from scapy.all import *
from Helpers.sniff_helper import sniffer_func, sniffer

IP_blocklist = "firehol_level1.netset"


if __name__ == '__main__':
    sniff_obj = sniffer()
    sniff(prn=sniffer_func)
