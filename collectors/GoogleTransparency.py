import requests
from termcolor import colored
import time


def init(domain):
    GTR = set()

    print(colored("[*]-Searching Certificate Transparency (crt.sh)...", "yellow"))

    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    for i in range(2):
        try:
            response = requests.get(url, params=params, headers=headers, timeout=20)
            if response.status_code == 200 and response.text:
                data = response.json()
                for entry in data:
                    val = entry.get("name_value", "")
                    if "\n" in val:
                        for v in val.split("\n"):
                            v = v.strip().lower()
                            if v and not v.startswith("*"):
                                GTR.add(v)
                    else:
                        val = val.strip().lower()
                        if val and not val.startswith("*"):
                            GTR.add(val)
                GTR = sorted(GTR)
                print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(GTR), "yellow")))
                return GTR
            elif response.status_code in [502, 504]:
                print(colored(f"  \__ Received {response.status_code}, retrying in 5s...", "yellow"))
                time.sleep(5)
            else:
                print(colored(f"  \__ HTTP {response.status_code}", "red"))
                return []
        except requests.exceptions.RequestException as e:
            print(colored(f"  \__ Error: {e}", "red"))
            return []

