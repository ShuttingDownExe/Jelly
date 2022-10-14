import netifaces

if __name__ == '__main__':
    gws = netifaces.gateways()
    print(gws)
    gateway = gws['default'][netifaces.AF_INET][0]
    MAC = str(gws['default'][netifaces.AF_INET][1]).replace("{", "").replace("}", "")
    print(gateway)
    print(MAC)
