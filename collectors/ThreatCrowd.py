import requests
from json import loads, JSONDecodeError
from termcolor import colored


def init(domain):
    TC = set()

    print(colored("[*]-Searching ThreatCrowd...", "yellow"))

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        result = requests.get(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/",
            params={"domain": domain},
            headers=headers,
            timeout=15,
        )
    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    try:
        RES = loads(result.text)
    except (ValueError, TypeError, JSONDecodeError):
        print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
        return []

    try:
        resp_code = int(RES.get("response_code", -1))

        if resp_code == 1:
            for sd in RES.get("subdomains", []):
                if sd:
                    TC.add(sd.strip().lower())

        print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(TC), "yellow")))
        return list(TC)

    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
