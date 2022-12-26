from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

from Guards.arp_guard import spoof_guard

from Helpers.http_helper import process_HTTP_packet
from Helpers.ip_helper import process_IP_packet
from Helpers.log_helper import logger



class sniffer_helper:
    ip_list = []

    def __init__(self):
        pass

    @staticmethod
    def sniffer_func(pkt):
        logger.info("[SNIFFER] Packet analysis started")
        wrpcap('PCAP_LOG.pcap', pkt, append=True)

        if ARP in pkt:
            spoof_guard(pkt)
        if IP in pkt:
            process_IP_packet(pkt, sniffer_helper.ip_list)

        if pkt.haslayer(HTTPRequest):
            process_HTTP_packet(pkt)
