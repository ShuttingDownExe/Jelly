from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

from Helpers.http_helper import process_HTTP_packet
from Helpers.ip_helper import process_IP_packet

from Guards.arp_guard import spoof_guard
from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, INFO


class sniffer_helper:
    ip_list = []

    def __init__(self):
        try:
            File = open("Helpers/firehol_level1.netset", "r")
            data = File.read()
            read_list = data.split("\n")
            sep = "/"
            data = [x.split(sep, 1)[0] for x in read_list]
            sniffer_helper.ip_list = data[33:]
            File.close()
        except:
            print_output("IP blocklist file missing", WARN)
            logger.error("[SNIFFER ERROR] UNABLE TO FIND BLOCKLIST FILE ")
        else:
            print_output("Blocklisted IP's loaded", INFO)

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
