import netifaces
from scapy.layers.dhcp import DHCP, DHCPOptions
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import rdpcap

from Helpers.output_helper import print_output, WARN, FUNC, NOTF
from Helpers.log_helper import logger


class arp_guard:
    default_gateway_IP = ""
    default_gateway_MAC = ""

    prev_pkt_MAC = ""
    prev_pkt_IP = ""

    def __init__(self):
        gws = netifaces.gateways()
        self.default_gateway_IP = str(gws['default'][netifaces.AF_INET][0])
        self.default_gateway_MAC = str(gws['default'][netifaces.AF_INET][1]) \
            .replace("{", "").replace("}", "")

    @staticmethod
    def spoof_guard(pkt):
        curr_pkt_MAC = pkt[ARP].hwsrc
        curr_pkt_IP = pkt[ARP].psrc

        if curr_pkt_MAC == arp_guard.prev_pkt_MAC and curr_pkt_IP != arp_guard.prev_pkt_IP:
            print_output(f"POSSIBLE INTRUSION ATTEMPT -> Type: ARP SPOOFING", WARN)
            logger.warn(f"[DETECTED] POSSIBLE ARP SPOOFING: ")

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
            logger.warn("[FAILED] Hostname could not be found: IP address missing from PCAP")
            return ""

        for pkt in pkts:
            if DHCP in pkt:
                if pkt[DHCP].options[0][1] == 1 or pkt[DHCP].options[0][1] == 3:
                    hostname = DHCPOptions.get(pkt[DHCP].options, 'hostname')
                    print_output(f"Hostname of possible attacker found: {hostname}", FUNC)
                    logger.info(f"[SUCCESS] Hostname of possible attacker found: {hostname}")
