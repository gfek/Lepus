import requests
from re import findall
from json import loads
from termcolor import colored


def parseSubject(subject, domain):
	hostnameRegex = "([\w\.\-]+\.%s)" % (domain.replace(".", "\."))
	hosts = findall(hostnameRegex, subject)

	return [host.lstrip(".") for host in hosts]


def init(domain):
	ENT = []

	print(colored("[*]-Searching Entrust Certificates...", "yellow"))

	url = "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain={0}&includeExpired=true&exactMatch=false&limit=5000".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}

	try:
		response = requests.get(url, headers=headers)
		response_json = loads(response.text.replace("\\u003d", "="))

		for item in response_json:
			ENT += parseSubject(item["subjectDN"], domain)

		ENT = set(ENT)

		print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(ENT), "yellow")))
		return ENT

	except ValueError as errv:
		print("  \__", colored(errv, "red"))
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
