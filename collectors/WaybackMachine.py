import requests
from urllib.parse import quote
from termcolor import colored
from urllib.parse import urlparse


def init(domain):
	WB = []

	print(colored("[*]-Searching WaybackMachine...", "yellow"))

	url = "https://web.archive.org/cdx/search/cdx?url=*.{0}&output=json&fl=original&collapse=urlkey".format(quote(domain))
	headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

	try:
		response = requests.get(url, headers=headers, timeout=20)
	except requests.exceptions.RequestException as err:
		print("  \__", colored(err, "red"))
		return []

	if response.status_code != 200:
		print("  \__ {0}: {1}".format(colored("Error", "red"), response.status_code))
		return []

	try:
		urls = response.json()
	except (ValueError, TypeError):
		print("  \__ {0}: {1}".format(colored("Error", "red"), "Invalid API response"))
		return []

	try:
		for url in urls:
			urlString = url[0]

			if domain in urlString:
				parsed_uri = urlparse(urlString)
				onlyDomain = "{uri.netloc}".format(uri=parsed_uri).split(":")[0]
				WB.append(onlyDomain)

		WB = set(WB)

		print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(WB), "yellow")))
		return WB

	except Exception:
		print("  \__", colored("Something went wrong!", "red"))
		return []
