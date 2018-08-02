import re
import requests
from bs4 import BeautifulSoup
from termcolor import colored


class DNSDumpsterAPI(object):
	_instance = None

	def __init__(self, arg=None):
		pass

	def __new__(cls, *args, **kwargs):
		if not cls._instance:
			cls._instance = super(DNSDumpsterAPI, cls).__new__(cls, *args, **kwargs)

		return cls._instance

	def search(self, domain):
		url = "https://dnsdumpster.com/"
		s = requests.session()

		try:
			req = s.get(url)
			soup = BeautifulSoup(req.content, "html.parser")
			csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
			cookies = {'csrftoken': csrf_middleware}
			headers = {'Referer': 'https://dnsdumpster.com/'}
			data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
			req = s.post(url, cookies=cookies, data=data, headers=headers)
			pattern = r'([\w\-][\w\-\.]+)\.%s' % (domain.replace('.', '\.'))
			res = re.findall(pattern, req.content)

			return list(res)

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


def init(domain):
	print colored("[*]-Searching DNSDumpster...", 'yellow')

	api = DNSDumpsterAPI()
	DD = ['.'.join([subdomain, domain]) for subdomain in set(api.search(domain))]

	print "  \__", colored("Unique subdomains found:", 'cyan'), colored(len(DD), 'yellow')

	return DD
