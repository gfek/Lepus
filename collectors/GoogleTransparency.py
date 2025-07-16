import requests
from re import findall
from termcolor import colored


def parseResponse(response, domain):
    try:
        # Parse the response to extract subdomains
        hostnameRegex = r"(?:CN=)(.*?)".format(domain.replace(".", "\."))
        hosts = findall(hostnameRegex, response)
        return [host.lstrip(".") for host in hosts]
    except Exception as e:
        print(f"Error parsing response: {e}")
        return []


import requests
from termcolor import colored
import time


def init(domain):
    GTR = []

    print(colored("[*]-Searching Google Transparency...", "yellow"))

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    for i in range(3):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.text:
                try:
                    data = response.json()
                    for entry in data:
                        GTR.append(entry["name_value"])
                    GTR = sorted(list(set(GTR)))
                    print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(GTR), "yellow")))
                    return GTR
                except ValueError:
                    print(colored(f"  \__ Error: Invalid JSON response from Google Transparency. Response text: {response.text}", "red"))
                    return []
            elif response.status_code in [502, 504]:
                print(colored(f"  \__ Received status code {response.status_code} from Google Transparency. Retrying in 5 seconds...", "yellow"))
                time.sleep(5)
                continue
            else:
                print(colored(f"  \__ Error: Received status code {response.status_code} from Google Transparency", "red"))
                return []
        except Exception as e:
            print(f"  \__ {colored('Error:', 'red')} {e}")
            return []
    return []

