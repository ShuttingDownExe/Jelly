import subprocess
from itertools import groupby

import netifaces

from scapy.layers.dhcp import DHCP, DHCPOptions
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.utils import rdpcap

from python_arptable import ARPTABLE

from Helpers.output_helper import print_output, WARN, FUNC, NOTF
from Helpers.log_helper import logger


class arp_guard:
    def __init__(self):
        gws = netifaces.gateways()
        self.default_gateway_IP = str(gws['default'][netifaces.AF_INET][0])
        self.my_IP = str()

    @staticmethod
    def is_all_equal(iterable):
        g = groupby(iterable)
        return next(g, True) and not next(g, False)

    @staticmethod
    def getMac(ip):
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
        result = srp(packet, timeout=3, verbose=False)[0]
        return result[0][1].hwsrc

    @staticmethod
    def spoof_guard(pkt):
        if pkt[ARP].op == 2:
            try:
                real_mac = arp_guard.getMac(pkt[ARP].psrc)
                resp_mac = pkt[ARP].hwsrc

                if real_mac != resp_mac:
                    print_output(f"POSSIBLE ARP SPOOFING ATTACK:-  Source Mac:{real_mac}    Fake Mac:{resp_mac}", WARN)
                    logger.warn(
                        f"[DETECTED] POSSIBLE ARP SPOOFING ATTACK:-   Source Mac:{real_mac}    Fake Mac:{resp_mac}")

                    arp_guard.arp_fix(pkt[ARP].psrc)
            except IndexError:
                pass

    @staticmethod
    def arp_fix(ip):
        print_output(f"Cleaning ARP Cache", FUNC)
        logger.info(f"[FUNC] Begun ARP Cleaner")
        ip_entries = []
        arp_table = ARPTABLE
        for i in arp_table:
            if i['IP address'] == ip:
                ip_entries.append(i)
        ip_macs = []
        for i in ip_entries:
            ip_macs.append(i['HW address'])

        if not arp_guard.is_all_equal(ip_macs):
            print_output(f"ARP CACHE POISONED", WARN)
            logger.critical(f"[ARP ATTACK] ARP HAS BEEN POISONED")

        result = subprocess.run('arp -d '+ip, capture_output = True, text=True, shell=True)
        print_output(f"ARP Cache Cleaned", FUNC)

