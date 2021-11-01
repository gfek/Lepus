import requests
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	SP = []

	print(colored("[*]-Searching Spyse...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	SPYSE_API_TOKEN = parser.get("Spyse", "SPYSE_API_TOKEN")

	if SPYSE_API_TOKEN == "":
		print("  \__", colored("No Spyse API token configured", "red"))
		return []

	headers = {
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
		"Authorization": "Bearer {0}".format(SPYSE_API_TOKEN),
		"accept": "application/json"
	}

	limit = 100
	offset = 0
	url = "https://api.spyse.com/v3/data/domain/subdomain?limit={0}&offset={1}&domain={2}".format(limit, offset, domain)

	try:
		response = requests.get(url, headers=headers)

		if response.status_code == 200:
			response_json = loads(response.text)

			for item in response_json["data"]["items"]:
				SP.append(item["name"])

			total_count = response_json["data"]["total_count"]

			if total_count > limit:
				offset += limit

				while offset < total_count:
					url = "https://api.spyse.com/v3/data/domain/subdomain?limit={0}&offset={1}&domain={2}".format(limit, offset, domain)

					response = requests.get(url, headers=headers)

					if response.status_code == 200:
						response_json = loads(response.text)

						for item in response_json["data"]["items"]:
							SP.append(item["name"])

						offset += limit

					elif response.status_code == 402:
						break;

			SP = set(SP)

			print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(SP), "yellow")))
			return SP

		elif response.status_code == 401:
			print("  \__", colored("Authentication error.", "red"))
			return []

		elif response.status_code == 402:
			print("  \__", colored("Request quota exceeded.", "red"))
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
