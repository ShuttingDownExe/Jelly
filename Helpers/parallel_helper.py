import multiprocessing

from Helpers.sniff_helper import sniffer_helper as snh

process_list = []


def chain(pkt):
    if len(process_list) < 5:
        process_list.append(multiprocessing.Process(target=snh.sniffer_func, args=(pkt,)))
        print("process added")
        process_list[len(process_list) - 1].start()
        print("process started")
    else:
        print("process queue full......waiting")
        process_list[0].join()
        process_list[0].stop()
        print("process 0 stopped..... shifting proces queue")
        for i in range(1, len(process_list)):
            process_list[i] = process_list[i + 1]

        print("re-chaining")
        chain(pkt)
