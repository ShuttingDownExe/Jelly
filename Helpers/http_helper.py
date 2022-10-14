from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP

from Helpers.log_helper import logger

from Helpers.output_helper import print_output


class http_helper:
    insecure_methods = ["PUT", "DELETE", "CONNECT", "TRACE"]

    def __init__(self):
        pass


def process_HTTP_packet(pkt):
    """
    Executes for HTTP packets only
    """
    print_output(f"HTTP REQUEST", "NOTF")
    url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
    ip = pkt[IP].src
    method = pkt[HTTPRequest].Method.decode()
    print_output(f"URL: <{url}> IP: <{ip}>", "UTIL")
    if str(method) in http_helper.insecure_methods:
        print_output(f"INSECURE METHOD USED: {method}", "WARN")
        logger.warn(f"[DETECTED] Insecure HTTP Request -> URL: <{url}> IP: {ip} METHOD: {method}")
