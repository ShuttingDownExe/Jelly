from python_arptable import ARPTABLE

if __name__ == "__main__":
    interfaceDict = next(item for item in ARPTABLE if item['Device'] == 'ens33')
    print(interfaceDict)



