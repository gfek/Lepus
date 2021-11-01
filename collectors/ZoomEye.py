import requests
from re import findall
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	ZOOM = []

	print(colored("[*]-Searching ZoomEye...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	ZOOMEYE_API_KEY = parser.get("ZoomEye", "ZOOMEYE_API_KEY")

	if ZOOMEYE_API_KEY == "":
		print("  \__", colored("No ZoomEye API key configured", "red"))
		return []

	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0", "API-KEY": ZOOMEYE_API_KEY}
	testFlag = True
	page = 1

	try:
		while testFlag:
			url = "https://api.zoomeye.org/host/search?query=hostname:{0}&page={1}".format(domain, page)
			response = requests.get(url, headers=headers)
			
			if response.status_code == 200 and loads(response.text)["available"] > 0:
				subdomains = findall("[-\.\w\d]+\.{0}".format(domain.replace(".", "\.")), response.text)

				if subdomains:
					for subdomain in subdomains:
						ZOOM.append("{0}.{1}".format(subdomain, domain))
				
				page = page + 1
			
			else:
				testFlag = False

		ZOOM = set(ZOOM)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(ZOOM), "yellow")))
		return ZOOM

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
