import requests
from re import findall
from json import loads
from base64 import b64encode
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    FOFA = []

    print(colored("[*]-Searching FOFA...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    FOFA_KEY = parser.get("FOFA", "FOFA_KEY")

    if not FOFA_KEY:
        print("  \__", colored("No FOFA API key configured", "red"))
        return []

    query = b64encode(f'domain="{domain}"'.encode()).decode()
    url = f"https://fofa.so/api/v1/search/all?key={FOFA_KEY}&qbase64={query}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("error"):
                print(f"  \__ {colored('FOFA API Error', 'red')}: {data['errmsg']}")
                return []
            for result in data.get('results', []):
                FOFA.extend(findall(rf'([\w\d][\w\d\-\.]*\.{domain.replace(".", "\\.")})', str(result)))
            print(f"  \__ {colored('Subdomains found', 'green')}: {len(set(FOFA))}")
        else:
            print(f"  \__ {colored('Error', 'red')}: {response.status_code}")
    except Exception as e:
        print(f"  \__ {colored('FOFA API Error', 'red')}: {e}")

    return list(set(FOFA))