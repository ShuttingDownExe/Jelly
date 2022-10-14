from colorama import init, Fore

init()

GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
RESET = Fore.RESET

INFO = "INFO"
NOTF = "NOTF"
UTIL = "UTIL"
FUNC = "FUNC"
WARN = "WARN"


def print_output(message, message_type):
    prepare_string = {
        "INFO": f"{GREEN}[*] " + message + f" {RESET}",
        "NOTF": f"\t{GREEN}[@] " + message + f" {RESET}",
        "UTIL": f"\t\t{BLUE}[#] " + message + f" {RESET}",
        "FUNC": f"\t\t{BLUE}[$] " + message + f" {RESET}",
        "WARN": f"{RED}[!] " + message + f" {RESET}",
    }

    print(prepare_string.get(message_type))
