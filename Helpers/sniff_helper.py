import schedule
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

from Helpers.http_helper import process_HTTP_packet
from Helpers.ip_helper import process_IP_packet
from Helpers.log_helper import logger

from Guards.arp_guard import spoof_guard
from Guards.ddos_guard import flood_guard, dos_guard, timed_check


class sniffer_helper:
    ip_list = []
    pkt_count = 0

    def __init__(self):
        pass



    def sniffer_func(self, pkt):
        logger.info("[SNIFFER] Packet analysis started")
        wrpcap('PCAP_LOG.pcap', pkt, append=True)

        self.pkt_count += 1

        if ARP in pkt:
            spoof_guard(pkt)
        if IP in pkt:
            process_IP_packet(pkt, sniffer_helper.ip_list)

        if pkt.haslayer(HTTPRequest):
            process_HTTP_packet(pkt)
