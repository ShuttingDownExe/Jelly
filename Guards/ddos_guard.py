import subprocess
from collections import Counter

from scapy.layers.inet import TCP, IP

from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, FUNC, INFO

count = Counter({})
pkt_lst = []


def isBadPkt(pkt):
    bad = True if TCP in pkt and pkt[TCP].flags & 2 else False
    return bad


def flood_guard(pkt):
    if IP in pkt and isBadPkt(pkt):
        pkt_lst.append(str(pkt[IP].src))

    count.update(pkt_lst)

    if count.most_common(1)[0][1] > 25:
        print_output(
            f"Possible DDOS attack:-   Source IP:{count.most_common(1)[0][0]}   Number of packets received:{count.most_common(1)[0][1]}",
            WARN)
        logger.critical(
            f"[DETECTED] Possible DDOS attack:-  Source IP:{count.most_common(1)[0][0]}   Number of packets received:{count.most_common(1)[0][1]}")
        ddos_fix(count.most_common(1)[0][0])


def ddos_fix(ip):
    print_output(f"Blocking TCP packets from {ip}", FUNC)
    result = subprocess.run('iptables -C INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                            capture_output=True, text=True, shell=True)
    if 'iptables: Bad rule' in result.stderr:
        subprocess.run('iptables -I INPUT -p tcp -s ' + ip + ' -j REJECT --reject-with tcp-reset',
                       capture_output=True, text=True, shell=True)
    print_output(f"Blocked", INFO)
    logger.info(f"[BLOCKED] SYN flood packets from {ip} blocked")
