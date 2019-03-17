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

	except EnvironmentError:
		print("  \__", colored("Missing Node.js runtime. Node is required and must be in the PATH (check with `node -v`). Your Node binary may be called `nodejs` rather than `node`, in which case you may need to run `apt install nodejs-legacy`.", "red"))
		return []
