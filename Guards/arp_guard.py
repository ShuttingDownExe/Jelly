import netifaces
from scapy.layers.dhcp import DHCP, DHCPOptions
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr, sendp, srp
from scapy.utils import rdpcap
import scapy.all as scapy
from Helpers.output_helper import print_output, WARN, FUNC, NOTF
from Helpers.log_helper import logger


class arp_guard:
    default_gateway_IP = ""

    my_IP = ""
    my_MAC = ""

    prev_pkt_MAC = ""
    prev_pkt_IP = ""

    def __init__(self):
        gws = netifaces.gateways()
        self.default_gateway_IP = str(gws['default'][netifaces.AF_INET][0])
        self.my_IP = str()

    @staticmethod
    def spoof_guard(pkt):
        curr_pkt_MAC = pkt[ARP].hwsrc
        curr_pkt_IP = pkt[ARP].psrc

        if curr_pkt_MAC == arp_guard.prev_pkt_MAC and curr_pkt_IP != arp_guard.prev_pkt_IP:
            print_output(f"POSSIBLE INTRUSION ATTEMPT -> Type: ARP SPOOFING", WARN)
            logger.warn(f"[DETECTED] POSSIBLE ARP SPOOFING: ")
            arp_guard.try_to_get_name(curr_pkt_IP)

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
            return

        for pkt in pkts:
            if DHCP in pkt:
                if pkt[DHCP].options[0][1] == 1 or pkt[DHCP].options[0][1] == 3:
                    hostname = DHCPOptions.get(pkt[DHCP].options, 'hostname')
                    print_output(f"Hostname of possible attacker found: {hostname}", FUNC)
                    logger.info(f"[SUCCESS] Hostname of possible attacker found: {hostname}")

    @staticmethod
    def arp_fix(def_gateway_ip, host_ip):
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

        #srp(pkt)



        pass
