import requests
from json import loads
from termcolor import colored


def init(domain):
	Sonar = []

	print(colored("[*]-Searching Rapid7 Open Data...", "yellow"))

	url = "http://dns.bufferover.run/dns?q=.{0}".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get(url, headers=headers)
		response_json = loads(response.text)

		if response_json["FDNS_A"]:
			for record in response_json["FDNS_A"]:
				Sonar += record.split(",")

		if response_json["RDNS"]:
			for record in response_json["RDNS"]:
				Sonar.append(record.split(",")[1])

		print("  \__ {0}: {1}".format(colored("subdomains found", "cyan"), colored(len(Sonar), "yellow")))
		return Sonar

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
