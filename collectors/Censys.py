import re
import requests
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	C = []

	print(colored("[*]-Searching Censys...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	API_URL = "https://www.censys.io/api/v1"
	UID = parser.get("Censys", "CENSYS_UID")
	SECRET = parser.get("Censys", "CENSYS_SECRET")

	if UID == "" or SECRET == "":
		print("  \__", colored("No Censys API credentials configured", "red"))
		return []

	else:
		payload = {"query": domain}

		try:
			res = requests.post(API_URL + "/search/certificates", json=payload, auth=(UID, SECRET))

			if res.status_code == 429:
				print("  \__", colored("Rate limit exceeded. See https://www.censys.io/account for rate limit details.", "red"))
				return C

			C = re.findall("CN=([\w\.\-\d]+)\." + domain, str(res.content))
			numberOfPages = re.findall("pages\":\s(\d+)?}", str(res.content))

			for page in range(2, int(numberOfPages[0]) + 1):
				payload = {"query": domain, "page": page}
				res = requests.post(API_URL + "/search/certificates", json=payload, auth=(UID, SECRET))
				tempC = re.findall("CN=([\w\.\-\d]+)\." + domain, str(res.content))
				C = C + tempC

			C = set(C)

			print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(C), "yellow")))
			return C

		except KeyError as errk:
			print("  \__", colored(errk, "red"))
			return []

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
