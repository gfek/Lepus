import requests
from urllib.parse import quote
from termcolor import colored
from configparser import RawConfigParser

def init(domain):
	HT = []
	
	parser = RawConfigParser()
	parser.read("config.ini")
	SECRET = parser.get("HackerTarget", "HACKERTARGET_KEY")

	if SECRET == "":
		print("  \__", colored("No HackerTarget API credentials configured, using without", "red"))

	print(colored("[*]-Searching HackerTarget...", "yellow"))

	url = "https://api.hackertarget.com/hostsearch/?apikey={0}&q={1}".format(SECRET,quote(domain))
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"}

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
