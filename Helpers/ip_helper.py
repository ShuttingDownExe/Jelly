from scapy.layers.inet import TCP, UDP, ICMP, IP

from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, FUNC, INFO


# from Helpers.sniff_helper import sniffer


class ip_helper:
    blocklist_file = str()
    ip_list = []
    protocols = []

    def __init__(self, blocklist):
        self.blocklist_file = blocklist
        try:
            File = open(str(self.blocklist_file), "r")
            data = File.read()
            read_list = data.split("\n")
            sep = "/"
            data = [x.split(sep, 1)[0] for x in read_list]
            self.ip_list = data[33:]
            File.close()
        except:
            print_output("IP blocklist file missing", WARN)
            logger.error("[SNIFFER ERROR] UNABLE TO FIND BLOCKLIST FILE ")
        else:
            print_output("Blocklisted IP's loaded", INFO)


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name


def TCP_block(ip):
    pass
    """
    result = subprocess.run('iptables -C INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                                capture_output=True, text=True, shell=True)
    """


def UDP_block(ip):
    pass
    """
    result = subprocess.run('iptables -C INPUT -p udp -s ' + ip + ' -j REJECT --reject-with icmp-port-unreachable',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p udp -s ' + ip + ' -j REJECT --reject-with icmp-port-unreachable',
                                capture_output=True, text=True, shell=True)
    """


def ICMP_block(ip):
    pass
    """
    result = subprocess.run('iptables -C INPUT -p icmp -s ' + ip + ' -j REJECT --reject-with icmp-host-unreachable',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p icmp -s ' + ip + ' -j REJECT --reject-with icmp-host-unreachable',
                                capture_output=True, text=True, shell=True)
    """


def ip_blocker(pkt, ip):
    print_output("Blocking...", WARN)
    if TCP in pkt:
        TCP_block(ip)
        print_output("Blocked: No action needed", FUNC)
        logger.warn(f"[BLOCKED] Blocklisted IP Address:   IP: {ip} Protocol: TCP")
    elif UDP in pkt:
        UDP_block(ip)
        print_output("Blocked: No action needed", FUNC)
        logger.warn(f"[BLOCKED] Blocklisted IP Address:   IP: {ip} Protocol: UDP")
    elif ICMP in pkt:
        ICMP_block(ip)
        print_output("Blocked: No action needed", FUNC)
        logger.warn(f"[BLOCKED] Blocklisted IP Address:   IP: {ip} Protocol: ICMP")
    else:
        print_output(f"UNKNOWN PROTOCOL: PLEASE MANUALLY BLOCK IP -> {ip}", WARN)
        print_output(f"PROTOCOL GUESS: {ip_helper.protocols[2]}", WARN)
        logger.critical(f"[BLOCKER ERROR] UNABLE TO BLOCK IP (Unknown Protocol):    IP: {ip} Protocol Guess: "
                        f"{ip_helper.protocols[2]}")


def process_IP_packet(pkt):
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    ip_helper.protocols = list(expand(pkt))
    print_output("Packet Sniffed -> Source: {0:20}\tDestination: {1}\t".format(ip_src, ip_dst), INFO)
    if str(ip_src) in ip_helper.ip_list:
        print_output(f"PACKET  FROM  BLOCKLISTED IP DETECTED  : -->{ip_src}<--", WARN)
        logger.warn(f"[DETECTED] Packet  FROM  malicious IP: {ip_src} ")
        ip_blocker(pkt, str(ip_src))
    elif str(ip_dst) in ip_helper.ip_list:
        print_output(f"PACKET   TO   BLOCKLISTED IP DETECTED  : -->{ip_src}<--", WARN)
        logger.warn(f"[DETECTED] Packet   TO   malicious IP: {ip_src} ")
        ip_blocker(pkt, str(ip_dst))
    else:
        return -1
