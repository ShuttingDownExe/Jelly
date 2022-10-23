from scapy.layers.inet import TCP, UDP, ICMP, IP
import subprocess

from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, FUNC, INFO


class ip_helper:
    blocklist_file = str()
    ip_list = []
    protocols = []

    def getBlocklist():
        try:
            File = open(str(blocklist_file), "r")
            data = File.read()
        read_list = data.split("\n")
        sep = "/"
        data = [x.split(sep, 1)[0] for x in read_list]
        ip_list = data[33:]
        File.close()

    except:
    print_output("IP blocklist file missing", WARN)
    logger.error("[SNIFFER ERROR] UNABLE TO FIND BLOCKLIST FILE ")

else:
print_output("Blocklisted IP's loaded", INFO)


def extract(pkt):
    counter = 0
    while True:
        layer = pkt.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1


def getProtocols(pkt):
    return_list = []
    for layer in list(extract(pkt)):
        return_list.append(layer.name)

    return [*set(return_list)]


def guessUnknownProtocol(protocols):
    protocol_guess_list = []
    for layer in protocols:
        if layer not in ["UDP", "TCP", "ICMP"]:
            protocol_guess_list.append(layer)

    return protocol_guess_list


def TCP_block(ip):
    result = subprocess.run('iptables -C INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                                capture_output=True, text=True, shell=True)


def UDP_block(ip):
    result = subprocess.run('iptables -C INPUT -p udp -s ' + ip + ' -j REJECT --reject-with icmp-port-unreachable',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p udp -s ' + ip + ' -j REJECT --reject-with icmp-port-unreachable',
                                capture_output=True, text=True, shell=True)


def ICMP_block(ip):
    result = subprocess.run('iptables -C INPUT -p icmp -s ' + ip + ' -j REJECT --reject-with icmp-host-unreachable',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        result = subprocess.run('iptables -I INPUT -p icmp -s ' + ip + ' -j REJECT --reject-with icmp-host-unreachable',
                                capture_output=True, text=True, shell=True)


def ip_blocker(pkt, ip, protocol_guess):
    print_output("Blocking...", WARN)
    logger.info("[STARTED] IP based Blocker")
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
        print_output(f"PROTOCOL GUESS: {protocol_guess}", WARN)
        logger.critical(f"[BLOCKER ERROR] UNABLE TO BLOCK IP (Unknown Protocol):    IP: {ip} Protocol Guess: "
                        f"{protocol_guess}")


def process_IP_packet(pkt):
    ip_helper("firehol_level1.netset")

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst

    ip_helper.protocols = getProtocols(pkt)

    print_output(
        "Packet Sniffed:\t Source: {0:20}->\t\tDestination: {1:20}=:=\t\t".format(ip_src, ip_dst) +
        "Layers Detected: {}".format(ip_helper.protocols), INFO)

    unknown_protocol_guess = guessUnknownProtocol(ip_helper.protocols)
    if str(ip_src) in ip_helper.ip_list:
        print_output(f"PACKET  FROM  BLOCKLISTED IP DETECTED  : -->{ip_src}<--", WARN)
        logger.warn(f"[DETECTED] Packet  FROM  malicious IP: {ip_src} ")
        ip_blocker(pkt, str(ip_src), unknown_protocol_guess)
    elif str(ip_dst) in ip_helper.ip_list:
        print_output(f"PACKET   TO   BLOCKLISTED IP DETECTED  : -->{ip_src}<--", WARN)
        logger.warn(f"[DETECTED] Packet   TO   malicious IP: {ip_src} ")
        ip_blocker(pkt, str(ip_dst), unknown_protocol_guess)
    else:
        pass
