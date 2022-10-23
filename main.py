#! /usr/bin/python3

from scapy.all import *

from Helpers.sniff_helper import sniffer_func, sniffer



if __name__ == '__main__':

    ip_helper("firehol_level1.netset")
    sniff_obj = sniffer()
    sniff(prn=sniffer_func)
