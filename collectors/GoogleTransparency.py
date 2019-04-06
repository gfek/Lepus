import requests
from re import findall
from termcolor import colored


def parseResponse(response, domain):
	try:
		token = response.split("\n]\n,[")[2].split("]\n")[0].split(",")[1].strip("\"")
		hostnameRegex = "([\w\.\-]+\.%s)" % (domain.replace(".", "\."))
		hosts = findall(hostnameRegex, response)

		return token, [host.lstrip(".") for host in hosts]

	except Exception:
		return "null", []


def init(domain):
	GTR = []

	print(colored("[*]-Searching Google Transparency...", "yellow"))

	baseURL = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0", "referrer": "https://transparencyreport.google.com/https/certificates"}
	token = ""

	try:
		while True:
			if not token:
				url = "".join([baseURL, "?domain=", domain, "&include_expired=true&include_subdomains=true"])

			else:
				url = "".join([baseURL, "/page?domain=", domain, "&include_expired=true&include_subdomains=true&p=", token])

			response = requests.get(url, headers=headers)
			token, hostnames = parseResponse(response.text, domain)

			for hostname in hostnames:
				GTR.append(hostname)

			if token == "null":
				break

		GTR = set(GTR)

		print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(GTR), "yellow")))
		return GTR

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
