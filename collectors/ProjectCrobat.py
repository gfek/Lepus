import requests
from json import loads
from termcolor import colored


def init(domain, ranges):
	Crobat = []

	print(colored("[*]-Searching Project Crobat...", "yellow"))

	url = "https://sonar.omnisint.io/subdomains/{0}".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get(url, headers=headers)

		if response.status_code == 200 and response.text.strip() != "null":
			data = loads(response.text)

			for d in data:
				Crobat.append(d)

		if ranges:
			for r in ranges.split(","):
				rev_url = "https://sonar.omnisint.io/reverse/{0}".format(r)
				response = requests.get(rev_url, headers=headers)

				if response.status_code == 200:
					data = loads(response.text)

					if "/" in r:
						for ip in data:
							for item in data[ip]:
								if domain in item:
									Crobat.append(item)

					else:
						data = loads(response.text)

						for d in data:
							if domain in d:
								Crobat.append(d)

		Crobat = set(Crobat)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(Crobat), "yellow")))
		return Crobat

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
