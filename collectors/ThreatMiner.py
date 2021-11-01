import requests
from json import loads
from termcolor import colored


def init(domain):
	TM = []

	print(colored("[*]-Searching Threatminer...", "yellow"))

	parameters = {"q": "{0}".format(domain), "rt": "5"}
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get("https://api.threatminer.org/v2/domain.php", params=parameters, headers=headers)

		if response.status_code == 200:
			data = loads(response.text)

			if data["status_message"] == "Results found.":
				for item in data["results"]:
					TM.append(item)

			TM = set(TM)

			print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(TM), "yellow")))
			return TM

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
