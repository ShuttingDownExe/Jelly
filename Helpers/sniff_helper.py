import schedule
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

from Helpers.http_helper import process_HTTP_packet
from Helpers.ip_helper import process_IP_packet
from Helpers.log_helper import logger

from Guards.arp_guard import spoof_guard
from Guards.ddos_guard import ddos_guard

class sniffer_helper:
    ip_list = []
    pkt_count = 0

    def __init__(self):
        pass

    @staticmethod
    def sniffer_func(pkt):
        logger.info("[SNIFFER] Packet analysis started")
        wrpcap('PCAP_LOG.pcap', pkt, append=True)

        ddos_guard.flood_guard(pkt)

        if ARP in pkt:
            spoof_guard(pkt)
        if IP in pkt:
            process_IP_packet(pkt, sniffer_helper.ip_list)

        if pkt.haslayer(HTTPRequest):
            process_HTTP_packet(pkt)
