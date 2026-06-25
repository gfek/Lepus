import requests
from json import loads
from termcolor import colored


def init(domain):
    CRT = set()

    print(colored("[*]-Searching CRT...", "yellow"))

    params = {"q": "%.{0}".format(domain), "output": "json"}
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        response = requests.get("https://crt.sh/", params=params, headers=headers, timeout=20)

        if response.status_code == 200:
            data = loads(response.text)

            for d in data:
                val = d.get("name_value", "")
                if "\n" in val:
                    for v in val.split("\n"):
                        v = v.strip().lower()
                        if v and not v.startswith("*"):
                            CRT.add(v)
                else:
                    val = val.strip().lower()
                    if val and not val.startswith("*"):
                        CRT.add(val)

            print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(CRT), "yellow")))
            return list(CRT)

        else:
            print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
            return []

    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    except ValueError:
        print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
        return []
    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
