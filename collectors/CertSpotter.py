import requests
from re import findall
from termcolor import colored


def parseResponse(response, domain):
    hostnameRegex = r"([\w\d][\w\d\-\.]*\.{0})".format(domain.replace(".", r"\."))
    hosts = findall(hostnameRegex, response)
    return [host.lstrip(".") for host in hosts]


def init(domain):
    CS = []

    print(colored("[*]-Searching CertSpotter...", "yellow"))

    base_url = "https://api.certspotter.com"
    next_link = "/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names".format(domain)
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    while next_link:
        try:
            response = requests.get(base_url + next_link, headers=headers, timeout=10)

            if response.status_code == 429:
                if CS:
                    break
                print("  \__", colored("Search rate limit exceeded.", "red"))
                return []

            if response.status_code != 200:
                print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
                return []

            CS += parseResponse(response.text, domain)

            try:
                link_header = response.headers.get("Link", "")
                if ";" in link_header:
                    next_link = link_header.split(";")[0].strip()
                    if next_link.startswith("<") and next_link.endswith(">"):
                        next_link = next_link[1:-1]
                    else:
                        break
                else:
                    break
            except (KeyError, IndexError):
                break

        except requests.exceptions.RequestException as err:
            print("  \__", colored(err, "red"))
            return []

        except Exception:
            print("  \__", colored("Something went wrong!", "red"))
            return []

    CS = set(CS)
    print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(CS), "yellow")))
    return CS
