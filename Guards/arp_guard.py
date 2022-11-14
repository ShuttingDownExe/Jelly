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
    def getMacTable(interface):
        interfaceDict = next(item for item in ARPTABLE if item['Device'] == interface)
        return interfaceDict

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

                    arp_guard.try_to_get_name(pkt[ARP].psrc)

                    arp_guard.arp_fix(pkt[ARP].psrc)
            except IndexError:
                pass

    @staticmethod
    def try_to_get_name(ip):
        pkts = rdpcap("PCAP_LOG.pcap")
        mac_lookup = ""

        print_output("Started Hostname guess function", NOTF)
        logger.info("[STARTED] DHCP Hostname extraction Attempt")

        for pkt in pkts:
            if DHCP in pkt:
                if pkt[DHCP].options[0][1] == 2:
                    if str(pkt[IP].dst) == str(ip):
                        mac_lookup = pkt[Ether].dst
                        print_output(f"MAC of possible attacker found: {mac_lookup}", FUNC)
                        logger.info(f"[FOUND] MAC Address of possible attacker: {mac_lookup}")

        if mac_lookup == "":
            print_output("IP of possible attacker could not be found in pcap logs", WARN)
            logger.warn("[FAILED] Hostname could not be found: IP address missing from PCAP logs")
            return

        for pkt in pkts:
            if DHCP in pkt:
                if pkt[DHCP].options[0][1] == 1 or pkt[DHCP].options[0][1] == 3:
                    hostname = DHCPOptions.get(pkt[DHCP].options, 'hostname')
                    print_output(f"Hostname of possible attacker found: {hostname}", FUNC)
                    logger.info(f"[SUCCESS] Hostname of possible attacker found: {hostname}")

    @staticmethod
    def arp_fix(ip):
        ip_entries = []
        arp_table = arp_guard.getMacTable('ens33')
        for i in arp_table:
            if i['IP address'] == ip:
                ip_entries = ip_entries.append(i)
        ip_macs = []
        for i in ip_entries:
            ip_macs = ip_macs.append(i['HW address'])

        if not arp_guard.is_all_equal(ip_macs):
            print_output(f"ARP CACHE POISONED", WARN)
            logger.critical(f"[ARP ATTACK] ARP HAS BEEN POISONED")

            print_output(f"-----FIXING-----", FUNC)
            subprocess.run('arp -d '+ip)


