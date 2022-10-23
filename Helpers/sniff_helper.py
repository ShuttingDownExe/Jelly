from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

from Helpers.http_helper import process_HTTP_packet
from Helpers.ip_helper import process_IP_packet, ip_helper

from Guards.arp_guard import arp_guard


class sniffer:
    pass


def sniffer_func(pkt):
    wrpcap('PCAP_LOG.pcap', pkt, append=True)

    if ARP in pkt:
        arp_guard.spoof_guard(pkt)

    if IP in pkt:
        process_IP_packet(pkt)

    if pkt.haslayer(HTTPRequest):
        process_HTTP_packet(pkt)
