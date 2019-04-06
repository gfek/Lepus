import utilities.MiscHelpers
import requests
from json import loads
from termcolor import colored


def init(domain):
	Sonar = []

	print(colored("[*]-Searching Rapid7 Open Data...", "yellow"))

	url = "http://dns.bufferover.run/dns?q=.{0}".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}

	try:
		response = requests.get(url, headers=headers)
		response_json = loads(response.text)

		if response_json["FDNS_A"]:
			for record in response_json["FDNS_A"]:
				Sonar += record.split(",")

		if response_json["RDNS"]:
			for record in response_json["RDNS"]:
				Sonar.append(record.split(",")[1])

		Sonar = utilities.MiscHelpers.filterDomain(domain, utilities.MiscHelpers.uniqueList(Sonar))

		print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(Sonar), "yellow")))
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
