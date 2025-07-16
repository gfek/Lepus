import shodan
from re import findall
from json import dumps
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    SD = []

    print(colored("[*]-Searching Shodan...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    SHODAN_API_KEY = parser.get("Shodan", "SHODAN_API_KEY")

    if not SHODAN_API_KEY:
        print("  \__", colored("No Shodan API key configured", "red"))
        return []

    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        results = api.search(f'hostname:"{domain}"')
        for result in results['matches']:
            SD.extend(findall(rf'([\w\d][\w\d\-\.]*\.{domain.replace(".", "\\.")})', result['data']))
        print(f"  \__ {colored('Subdomains found', 'green')}: {len(set(SD))}")
    except shodan.APIError as e:
        print(f"  \__ {colored('Shodan API Error', 'red')}: {e}")

    return list(set(SD))