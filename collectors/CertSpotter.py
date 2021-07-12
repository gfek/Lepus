import requests
from re import findall
from termcolor import colored


def parseResponse(response, domain):
	hostnameRegex = "([\w\d][\w\d\-\.]*\.{0})".format(domain.replace(".", "\."))
	hosts = findall(hostnameRegex, response)

	return [host.lstrip(".") for host in hosts]


def init(domain):
	CS = []

	print(colored("[*]-Searching CertSpotter...", "yellow"))

	base_url = "https://api.certspotter.com"
	next_link = "/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	while next_link:
		try:
			response = requests.get(base_url + next_link, headers=headers)

			if response.status_code == 429 and len(CS) == 0:
				print("  \__", colored("Search rate limit exceeded.", "red"))
				return []

			elif response.status_code == 429 and len(CS) > 0:
				break

			CS += parseResponse(response.text, domain)

			try:
				next_link = response.headers["Link"].split(";")[0][1:-1]

			except KeyError:
				break

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

	CS = set(CS)

	print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(CS), "yellow")))
	return CS
