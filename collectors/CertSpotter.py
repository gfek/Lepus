import requests
from re import findall
from termcolor import colored


def parseResponse(response, domain):
	hostnameRegex = "([\w\.\-]+\.%s)" % (domain.replace(".", "\."))
	hosts = findall(hostnameRegex, str(response))

	return [host.lstrip(".") for host in hosts]


def init(domain):
	CS = []

	print(colored("[*]-Searching CertSpotter...", "yellow"))

	base_url = "https://api.certspotter.com"
	next_link = "/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names".format(domain)
	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}

	while next_link:
		try:
			response = requests.get(base_url + next_link, headers=headers)

			if response.status_code == 429:
				print("  \__", colored("Search rate limit exceeded.", "red"))
				return []

			CS += parseResponse(response.content, domain)

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

	print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(CS), "yellow")))
	return CS
