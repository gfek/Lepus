import requests
import ipaddress
from termcolor import colored


def get_sld(domain):
    parts = domain.split(".")
    if len(parts) <= 2:
        return parts[0] if len(parts) == 2 else domain
    known_two_part_tlds = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "nhs.uk",
        "sch.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "org.br", "net.br", "gov.br",
        "co.nz", "net.nz", "org.nz",
        "co.za", "org.za", "net.za", "gov.za", "ac.za",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
        "com.mx", "org.mx", "net.mx", "gob.mx",
        "co.kr", "or.kr", "ne.kr",
        "com.ar", "net.ar", "org.ar", "gov.ar",
    }
    tld = ".".join(parts[-2:]).lower()
    if tld in known_two_part_tlds:
        return parts[-3] if len(parts) >= 3 else parts[0]
    return parts[-2]


def init(domain):
    R = []
    print(colored("\n[*]-Searching RIPE database for networks...", "yellow"))

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}
    sld = get_sld(domain)
    searchUrl = "https://rest.db.ripe.net/search.json?query-string={0}&flags=no-referenced&flags=no-irt&source=RIPE".format(sld)

    try:
        response = requests.get(searchUrl, headers=headers, timeout=15)
    except requests.exceptions.RequestException as err:
        print("  \__", colored(err, "red"))
        return []

    if response.status_code != 200:
        print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
        return []

    try:
        data = response.json()
        objects = data.get("objects", {}).get("object", []) if isinstance(data.get("objects", {}).get("object", []), list) else [data.get("objects", {}).get("object", {})]
        for obj in objects:
            attrs = {a.get("name"): a.get("value") for a in obj.get("attributes", {}).get("attribute", []) if isinstance(obj.get("attributes", {}).get("attribute", []), list)}
            value = attrs.get("value", "")
            if value and "-" in value:
                parts = value.split(" - ")
                if len(parts) == 2:
                    try:
                        startip = ipaddress.IPv4Address(parts[0].strip())
                        endip = ipaddress.IPv4Address(parts[1].strip())
                        for cidr in ipaddress.summarize_address_range(startip, endip):
                            R.append(str(cidr))
                    except (ipaddress.AddressValueError, ValueError):
                        pass

        R = list(set(R))

        print("  \__ {0}: {1}".format(colored("Networks found", "cyan"), colored(len(R), "yellow")))
        return R

    except (ValueError, TypeError):
        print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
        return []
    except Exception:
        print("  \__", colored("Something went wrong!", "red"))
        return []
