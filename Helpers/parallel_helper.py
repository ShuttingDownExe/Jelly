import multiprocessing

from Helpers.sniff_helper import sniffer_helper as snh

process_list = []


def chain(pkt):
    if len(process_list) < 20:
        process_list.append(multiprocessing.Process(target=snh.sniffer_func, args=(snh,pkt)))
        process_list[len(process_list) - 1].start()
    else:
        process_list[0].join()
        process_list.remove(process_list[0])
        chain(pkt)
