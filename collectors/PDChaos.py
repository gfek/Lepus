import requests
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	PDCH = []

	print(colored("[*]-Searching Project Discovery Chaos...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	CHAOS_KEY = parser.get("PDChaos", "CHAOS_API_KEY")

	if CHAOS_KEY == "":
		print("  \__", colored("No Project Discovery Chaos API key configured", "red"))
		return []

	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "Authorization": CHAOS_KEY}
	url = "https://dns.projectdiscovery.io/dns/{0}/subdomains".format(domain)

	try:
		response = requests.get(url, headers=headers).text
		subdomains = loads(response)["subdomains"]

		for subdomain in subdomains:
			if subdomain:
				PDCH.append("{0}.{1}".format(subdomain, domain))

		PDCH = set(PDCH)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(PDCH), "yellow")))
		return PDCH

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
