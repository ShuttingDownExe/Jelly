from Helpers import sniffer_helper as snh
from Helpers.log_helper import logger
from Helpers.output_helper import print_output, WARN, INFO


def get_blocklist():
    try:
        File = open("Helpers/firehol_level1.netset","r")
        data = File.read()
        read_list = data.split("\n")
        sep = "/"
        data = [x.split(sep, 1)[0] for x in read_list]
        snh.ip_list = data[33:]
    except:
        print_output("IP blocklist file missing", WARN)
        logger.error("[SNIFFER ERROR] UNABLE TO FIND BLOCKLIST FILE ")
    else:
        print_output("Blocklisted IP's loaded", INFO)