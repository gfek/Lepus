import requests
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	SP = []

	print(colored("[*]-Searching Spyse API...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	SPYSE_API_TOKEN = parser.get("Spyse", "SPYSE_API_TOKEN")

	if SPYSE_API_TOKEN == "":
		print("  \__", colored("No Spyse API token configured", "red"))
		return []

	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}
	url = "https://api.spyse.com/v1/subdomains?api_token={0}&domain={1}&page=".format(SPYSE_API_TOKEN, domain)

	try:
		page = 1

		while(True):
			response = requests.get(url + str(page), headers=headers, verify=False)
			response_json = loads(response.text)

			if "records" not in response.text or len(response_json["records"]) == 0:
				break

			else:
				for record in response_json["records"]:
					SP.append(record["domain"])

				page += 1

		SP = set(SP)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(SP), "yellow")))
		return SP

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
