#! /usr/bin/python3

from scapy.all import *
from Helpers.sniff_helper import sniffer_helper

IP_blocklist = "firehol_level1.netset"


if __name__ == '__main__':
    snh = sniffer_helper()
    sniff(prn=snh.sniffer_func)
