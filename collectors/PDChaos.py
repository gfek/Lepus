import requests
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    PDCH = set()

    print(colored("[*]-Searching Project Discovery Chaos...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    CHAOS_KEY = parser.get("PDChaos", "CHAOS_API_KEY")

    if not CHAOS_KEY:
        print("  \__", colored("No Project Discovery Chaos API key configured", "red"))
        return []

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "Authorization": CHAOS_KEY}
    url = "https://dns.projectdiscovery.io/dns/{0}/subdomains".format(domain)

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    if response.status_code != 200:
        print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
        return []

    try:
        subdomains = loads(response.text).get("subdomains", [])

        for subdomain in subdomains:
            if subdomain:
                PDCH.add("{0}.{1}".format(subdomain, domain))

        print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(PDCH), "yellow")))
        return list(PDCH)

    except (ValueError, TypeError):
        print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
        return []
    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
