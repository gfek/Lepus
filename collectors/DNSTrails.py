import requests
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    DT = set()

    print(colored("[*]-Searching DNSTrails...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    DNSTrails_API_KEY = parser.get("DNSTrails", "DNSTRAILS_API_KEY")

    if not DNSTrails_API_KEY:
        print("  \__", colored("No DNSTrails API key configured", "red"))
        return []

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "APIKEY": DNSTrails_API_KEY}
    url = "https://api.securitytrails.com/v1/domain/{}/subdomains".format(domain)

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 429:
            print("  \__", colored("Rate limited.", "red"))
            return []

        if response.status_code != 200:
            print("  \__", colored(f"HTTP {response.status_code}", "red"))
            return []

        payload = loads(response.text)

        for item in payload.get("subdomains", []):
            if item:
                DT.add("{}.{}".format(item, domain))

        print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(DT), "yellow")))
        return list(DT)

    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
