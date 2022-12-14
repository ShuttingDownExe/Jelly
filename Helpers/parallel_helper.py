import multiprocessing

from Helpers.sniff_helper import sniffer_helper as snh


from Guards.ddos_guard import flood_guard

process_list = []

def clean():
    for p in process_list:
        if not p.is_alive():
            process_list.pop(process_list.index(p))



def chain(pkt):
    flood_guard(pkt)

    if len(process_list) > 20:
        clean()

    process_list.append(multiprocessing.Process(target= snh.sniffer_func, args=pkt))
    process_list[len(process_list) - 1].start()
