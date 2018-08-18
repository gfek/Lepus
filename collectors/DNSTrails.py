import requests
from termcolor import colored
from ConfigParser import SafeConfigParser


def init(domain):
	DT = []

	print colored("[*]-Searching DNSTrails...", 'yellow')

	parser = SafeConfigParser()
	parser.read('config.ini')
	DNSTrails_API_KEY = parser.get('DNSTrails', 'DNSTrails_API_KEY')

	if DNSTrails_API_KEY == "":
		print "  \__", colored("No DNSTrails API key configured", 'red')
		return []

	else:
		headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0', 'content-type': 'application/json', 'APIKEY': DNSTrails_API_KEY}
		url = 'https://api.securitytrails.com/v1/domain/{}/subdomains'.format(domain)

		try:
			response = requests.get(url, headers=headers)
			payload = response.json()

			for k, v in payload.items():
				if v:
					for dnsvalue in v:
						DT.append('.'.join([dnsvalue, domain]))

			DT = set(DT)

			print "  \__", colored("Unique subdomains found:", 'cyan'), colored(len(DT), 'yellow')
			return DT

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
