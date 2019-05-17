from cfscrape import create_scraper
from bs4 import BeautifulSoup
from termcolor import colored


def init(domain):
	dnsdb = []

	print(colored("[*]-Searching DNSDB...", "yellow"))

	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}
	url = "http://www.dnsdb.org/{0}/".format(domain)

	try:
		scrapper = create_scraper()
		response = scrapper.get(url, headers=headers)

		soup = BeautifulSoup(response.text, "html.parser")

		for link in soup.findAll("a"):
			try:
				if link.string is not None:
					dnsdb.append(link.string)

			except KeyError:
				pass

		dnsdb = set(dnsdb)

		print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(dnsdb), "yellow")))
		return dnsdb

	except EnvironmentError as erre:
		print("  \__", colored(erre, "red"))
		return []

	except ValueError as errv:
		print("  \__", colored(errv, "red"))
		return []

	except Exception:
		print("  \__", colored("Something went wrong!", "red"))
		return []
