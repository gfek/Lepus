import requests
from json import loads
from termcolor import colored


def init(domain):
    TM = set()

    print(colored("[*]-Searching Threatminer...", "yellow"))

    params = {"q": domain, "rt": "5"}
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        response = requests.get("https://api.threatminer.org/v2/domain.php", params=params, headers=headers, timeout=15)

        if response.status_code == 200:
            data = loads(response.text)

            if data.get("status_message") == "Results found.":
                for item in data.get("results", []):
                    if item:
                        TM.add(item.strip().lower())

            print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(TM), "yellow")))
            return list(TM)

        else:
            print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
            return []

    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
