import requests
from urllib import quote
from termcolor import colored
from urlparse import urlparse


def init(domain):
	WB = []

	print colored("[*]-Searching WaybackMachine...", 'yellow')

	url = "http://web.archive.org/cdx/search/cdx?url=*.{0}&output=json&fl=original&collapse=urlkey".format(quote(domain))
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'}

	try:
		response = requests.get(url, headers=headers)
		urls = response.json()

		for url in urls:
			urlString = url[0]

			if domain in urlString:
				parsed_uri = urlparse(urlString)
				onlyDomain = "{uri.netloc}".format(uri=parsed_uri).split(":")[0]
				WB.append(onlyDomain)

			else:
				pass

		WB = set(WB)

		print "  \__", colored("Unique subdomains found:", 'cyan'), colored(len(WB), 'yellow')
		return WB

	except requests.exceptions.RequestException as err:
		print "  \__", colored(err, 'red')
		return []

	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh, 'red')
		return []

	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc, 'red')
		return []

	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt, 'red')
		return []
