import requests
from json import loads
from urllib.parse import quote
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    riddler = set()

    print(colored("[*]-Searching Riddler...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    RIDDLER_USERNAME = parser.get("Riddler", "RIDDLER_USERNAME")
    RIDDLER_PASSWORD = parser.get("Riddler", "RIDDLER_PASSWORD")

    if not RIDDLER_USERNAME or not RIDDLER_PASSWORD:
        print("  \__", colored("No Riddler API credentials configured", "red"))
        return []

    auth = {"email": RIDDLER_USERNAME, "password": RIDDLER_PASSWORD}
    auth_url = "https://riddler.io/auth/login"
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "content-type": "application/json"}

    try:
        auth_response = requests.post(auth_url, json=auth, headers=headers, timeout=15)
        auth_response_json = loads(auth_response.text)

        if auth_response_json.get("meta", {}).get("code") != 200:
            print("  \__", colored("Invalid Riddler API credentials.", "red"))
            return []

        auth_token = auth_response_json["response"]["user"]["authentication_token"]
        search = {"query": "pld:{0}".format(quote(domain)), "output": "host"}
        search_url = "https://riddler.io/api/search"
        headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "content-type": "application/json", "authentication-token": auth_token}

        search_response = requests.post(search_url, json=search, headers=headers, timeout=15)

        if search_response.status_code == 500:
            print("  \__", colored("Internal Server Error.", "red"))
            return []

        search_response_json = loads(search_response.text)

        for item in search_response_json:
            host = item.get("host", "")
            if host:
                riddler.add(host.strip().lower())

        print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(riddler), "yellow")))
        return list(riddler)

    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
