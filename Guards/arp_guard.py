import netifaces
from scapy.layers.l2 import ARP

from Helpers.output_helper import print_output, WARN
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
    def try_to_get_name(pkt, ip):
        pass

