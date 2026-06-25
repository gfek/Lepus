import requests
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    PT = []

    print(colored("[*]-Searching PassiveTotal...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    PT_KEY = parser.get("PassiveTotal", "PT_KEY")
    PT_SECRET = parser.get("PassiveTotal", "PT_SECRET")

    if not PT_KEY or not PT_SECRET:
        print("  \__", colored("No PassiveTotal API credentials configured", "red"))
        return []

    auth = (PT_KEY, PT_SECRET)
    url = f"https://api.passivetotal.org/v2/enrichment/subdomains?query={domain}"

    try:
        response = requests.get(url, auth=auth, timeout=10)
        if response.status_code == 200:
            PT = response.json().get('subdomains', [])
            print(f"  \__ {colored('Subdomains found', 'green')}: {len(PT)}")
        else:
            print(f"  \__ {colored('Error', 'red')}: {response.status_code}")
    except Exception as e:
        print(f"  \__ {colored('PassiveTotal API Error', 'red')}: {e}")

    return PT