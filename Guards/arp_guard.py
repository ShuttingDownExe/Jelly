import os
import re

import netifaces
from scapy.layers.dhcp import DHCP, DHCPOptions
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.utils import rdpcap
from Helpers.output_helper import print_output, WARN, FUNC, NOTF
from Helpers.log_helper import logger


class arp_guard:
    def __init__(self):
        gws = netifaces.gateways()
        self.default_gateway_IP = str(gws['default'][netifaces.AF_INET][0])
        self.my_IP = str()

    @staticmethod
    def getMac(ip):
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
        result = srp(packet, timeout=3, verbose=False)[0]
        return result[0][1].hwsrc

    @staticmethod
    def getMacTable():
        ret = []
        commandOutput = os.popen('arp -a').read()

        lines = commandOutput.split('\n')
        lines = [e for e in lines if (not 'ress' in e)]

        ACTIVE_IFACE = None
        ID = 1

        for line in lines:

            if line == '':
                continue

            if line[:9] == 'Interface':
                ACTIVE_IFACE = line.split(' ')[1]

            else:
                if ACTIVE_IFACE is None:
                    continue
                line = re.sub(r' +', r' ', line).strip()
                IPV4, PHYSICAL, CACHE_TYPE = line.split(' ')
                CACHE_TYPE = 'dynamic' if CACHE_TYPE[:4] == 'dyna' else 'static'
                ret.append([ID, ACTIVE_IFACE, IPV4, PHYSICAL, CACHE_TYPE])
                ID += 1

            return ret

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

                    arp_guard.arp_fix()
            except IndexError:
                pass

    @staticmethod
    def try_to_get_name(ip):
        pkts = rdpcap("../PCAP_LOG.pcap")
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
    def arp_fix():
        pkt = Ether() / ARP()
        # --->[ Ether ]<--- #
        pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        pkt[Ether].src = "d8:c0:a6:38:c7:65"
        # --->[ ARP ]<--- #
        pkt[ARP].hwtype = 0x1
        pkt[ARP].ptype = "IPv4"
        pkt[ARP].hwlen = 6
        pkt[ARP].plen = 4
        pkt[ARP].op = 1
        pkt[ARP].hwsrc = "d8:c0:a6:38:c7:65"
        pkt[ARP].hwdst = "00:00:00:00:00:00"
        pkt[ARP].psrc = "192.168.0.103"
        pkt[ARP].pdst = "192.168.0.1"

        pkt.show()

        # srp(pkt)

        pass
