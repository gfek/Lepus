import requests
from re import findall
from json import loads
from base64 import b64encode
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	FOFA = []

	print(colored("[*]-Searching FOFA...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	FOFA_EMAIL = parser.get("FOFA", "FOFA_EMAIL")
	FOFA_KEY = parser.get("FOFA", "FOFA_KEY")

	if FOFA_EMAIL == "" or FOFA_KEY == "":
		print("  \__", colored("No FOFA API credentials configured", "red"))
		return []

	size = 10000
	page = 1
	encodedDomain = b64encode(domain.encode("utf8")).decode("utf8")
	parameters = {"email": FOFA_EMAIL, "key": FOFA_KEY, "qbase64": encodedDomain, "page": page, "size": size, "full": "true", "fields": "host,title,domain,header,banner,cert"}
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get("https://fofa.so/api/v1/search/all", params=parameters, headers=headers)

		if response.status_code == 200 and loads(response.text)["error"] is False:
			data = loads(response.text)

			resultNumber = data["size"]

			if resultNumber % size == 0:
				pagesToRequest = resultNumber // size
			else:
				pagesToRequest = (resultNumber // size) +1

			while page <= pagesToRequest:

				if page != 1:
					parameters = {"email": FOFA_EMAIL, "key": FOFA_KEY, "qbase64": encodedDomain, "page": page, "size": size, "full": "true", "fields": "host,title,domain,header,banner,cert"}
					response = requests.get("https://fofa.so/api/v1/search/all", params=parameters, headers=headers)

				if loads(response.text)["error"] is False:
					FOFA.extend([item.lower() for item in findall("([\w\d][\w\d\-\.]*\.{0})".format(domain.replace(".", "\.")), response.text)])
					page += 1
				else:
					break

			FOFA = set(FOFA)

			print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(FOFA), "yellow")))
			return FOFA

		else:
			print("  \__", colored("Something went wrong!", "red"))
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
