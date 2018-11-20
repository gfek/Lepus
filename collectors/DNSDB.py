import requests
from bs4 import BeautifulSoup
from termcolor import colored


def init(domain):
	dnsdb = []

	print colored("[*]-Searching DNSDB...", "yellow")

	headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}
	url = "http://www.dnsdb.org/{}/".format(domain)

	try:
		response = requests.get(url, headers=headers)
		name_soup = BeautifulSoup(response.text, "html.parser")

		for link in name_soup.findAll("a"):
			try:
				if link.string is not None:
					dnsdb.append(link.string)

			except KeyError:
				pass

		dnsdb = set(dnsdb)

		print "  \__", colored("Unique subdomains found:", "cyan"), colored(len(dnsdb), "yellow")
		return dnsdb

	except requests.exceptions.RequestException as err:
		print "  \__", colored(err, "red")
		return []

	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh, "red")
		return []

	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc, "red")
		return []

	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt, "red")
		return []
