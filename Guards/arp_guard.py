import subprocess
from itertools import groupby

from python_arptable import ARPTABLE
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, NOTF


def is_all_equal(iterable):
    g = groupby(iterable)
    return next(g, True) and not next(g, False)


def getMac(ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(packet, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


def spoof_guard(pkt):
    if pkt[ARP].op == 2:
        try:
            real_mac = getMac(pkt[ARP].psrc)
            resp_mac = pkt[ARP].hwsrc
            if real_mac != resp_mac:
                print_output(f"POSSIBLE ARP SPOOFING ATTACK:-  Source Mac:{real_mac}    Fake Mac:{resp_mac}", WARN)
                logger.warn(f"[DETECTED] POSSIBLE ARP SPOOFING ATTACK:-   Source Mac:{real_mac}    Fake Mac:{resp_mac}")
                arp_fix(pkt[ARP].psrc)
        except IndexError:
            pass


def arp_fix(ip):
    print_output(f"Cleaning ARP Cache", NOTF)
    logger.info(f"[FUNC] Begun ARP Cleaner")
    ip_entries = []
    arp_table = ARPTABLE
    for i in arp_table:
        if i['IP address'] == ip:
            ip_entries.append(i)
    ip_macs = []
    for i in ip_entries:
        ip_macs.append(i['HW address'])

    if not is_all_equal(ip_macs):
        print_output(f"ARP CACHE POISONED", WARN)
        logger.critical(f"[ARP ATTACK] ARP HAS BEEN POISONED")

    result = subprocess.run('arp -d ' + ip, capture_output=True, text=True, shell=True)
    print_output(f"ARP Cache Cleaned", NOTF)
    logger.info(f"[FIXED] ARP Cache cleaned")
