import requests
from re import findall
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    C = []

    print(colored("[*]-Searching Censys...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    API_KEY = parser.get("Censys", "CENSYS_API_KEY")

    if not API_KEY:
        print("  \__", colored("No Censys API key configured", "red"))
        return []

    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY}
    url = "https://search.censys.io/api/v2/hosts/search"
    data = {"q": domain, "per_page": 100}

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            data = response.json()
            for result in data.get("result", {}).get("hits", []):
                C.extend(findall(rf'([\w\d][\w\d\-\.]{domain.replace(".", "\\.")})', str(result)))
            print(f"  \__ {colored('Subdomains found', 'green')}: {len(set(C))}")
        else:
            print(f"  \__ {colored('Error', 'red')}: {response.status_code}")
    except Exception as e:
        print(f"  \__ {colored('Censys API Error', 'red')}: {e}")

    return list(set(C))