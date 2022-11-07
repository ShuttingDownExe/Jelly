import os
import re

if __name__ == '__main__':
    ret = []
    commandOutput = os.popen('arp -a').read()

    lines = commandOutput.split('\n')
    lines = [e for e in lines if (not 'ress' in e)]

    ACTIVE_IFACE = None
    ID = 1

    for line in lines:

        if line == '':
            continue

        if line[:9] == 'Interface':
            ACTIVE_IFACE = line.split(' ')[1]

        else:
            if ACTIVE_IFACE is None:
                continue
            line = re.sub(r' +', r' ', line).strip()
            IPV4, PHYSICAL, CACHE_TYPE = line.split(' ')
            CACHE_TYPE = 'dynamic' if CACHE_TYPE[:4] == 'dyna' else 'static'
            ret.append([ID, ACTIVE_IFACE, IPV4, PHYSICAL, CACHE_TYPE])
            ID += 1

    for entry in ret:
        print(entry)
