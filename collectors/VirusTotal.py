import requests
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    VT = set()

    print(colored("[*]-Searching VirusTotal...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    VT_API_KEY = parser.get("VirusTotal", "VT_API_KEY")

    if not VT_API_KEY:
        print("  \__", colored("No VirusTotal API key configured", "red"))
        return []

    params = {"domain": domain, "apikey": VT_API_KEY}
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=params, headers=headers, timeout=10)
    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    try:
        response_dict = response.json()
    except (ValueError, TypeError):
        print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
        return []

    if response.status_code != 200:
        print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
        return []

    try:
        for sd in response_dict.get("subdomains", []):
            if sd:
                VT.add(sd.strip().lower())

        print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(VT), "yellow")))
        return list(VT)
    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
