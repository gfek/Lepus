import requests
import ipaddress
from re import findall
from termcolor import colored

def init(domain):
	R = []
	print(colored("\n[*]-Searching RIPE database for networks...", "yellow"))

	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}
	searchUrl = "https://rest.db.ripe.net/search.json?query-string={0}&flags=no-referenced&flags=no-irt&source=RIPE".format(domain.split(".")[-2])

	try:
		response = requests.get(searchUrl, headers=headers)
		IPranges = findall("value\"\s:\s\"(\d+\.\d+\.\d+\.\d+\s-\s\d+\.\d+\.\d+\.\d+)\"", response.text)

		for arange in IPranges:
			startip = ipaddress.IPv4Address(arange.split(" - ")[0])
			endip = ipaddress.IPv4Address(arange.split(" - ")[1])
			cidr = str([ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)][0])
			R.append(cidr)
		
		R = list(set(R))

		print("  \__ {0}: {1}".format(colored("Networks found", "cyan"), colored(len(R), "yellow")))
		return R

	except requests.exceptions.RequestException as err:
		print("  \__", colored(err, "red"))
		return []

	except requests.exceptions.HTTPError as errh:
		print("  \__", colored(errh, "red"))
		return []

	except requests.exceptions.ConnectionError as errc:
		print("  \__", colored(errc, "red"))
		return []

	except requests.exceptions.Timeout as errt:
		print("  \__", colored(errt, "red"))
		return []

	except Exception:
		print("  \__", colored("Something went wrong!", "red"))
		return []
