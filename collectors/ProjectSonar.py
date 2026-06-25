import requests
from json import loads, JSONDecodeError
from termcolor import colored


def init(domain):
    Sonar = set()

    print(colored("[*]-Searching Rapid7 Open Data...", "yellow"))

    url = "https://dns.bufferover.run/dns?q=.{0}".format(domain)
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        response = requests.get(url, headers=headers, timeout=20)
    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    try:
        response_json = loads(response.text)
    except (ValueError, TypeError, JSONDecodeError):
        print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
        return []

    try:
        if response_json.get("FDNS_A"):
            for record in response_json["FDNS_A"]:
                parts = record.split(",")
                if len(parts) >= 2:
                    Sonar.add(parts[1].strip().lower())

        if response_json.get("RDNS"):
            for record in response_json["RDNS"]:
                parts = record.split(",")
                if len(parts) >= 2:
                    Sonar.add(parts[1].strip().lower())

        print("  \__ {0}: {1}".format(colored("subdomains found", "cyan"), colored(len(Sonar), "yellow")))
        return list(Sonar)

    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
