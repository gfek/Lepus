import requests
from urllib.parse import quote
from termcolor import colored


def init(domain):
	HT = []

	print(colored("[*]-Searching HackerTarget...", "yellow"))

	url = "https://api.hackertarget.com/hostsearch/?q={0}".format(quote(domain))
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get(url, headers=headers).text
		hostnames = [result.split(",")[0] for result in response.split("\n")]

		for hostname in hostnames:
			if hostname:
				HT.append(hostname)

		HT = set(HT)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(HT), "yellow")))
		return HT

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
