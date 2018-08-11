import requests
from json import loads
from urllib import quote
from termcolor import colored
from ConfigParser import SafeConfigParser


def init(domain):
	riddler = []

	print colored("[*]-Searching Riddler...", 'yellow')

	parser = SafeConfigParser()
	parser.read('config.ini')
	RIDDLER_USERNAME = parser.get('Riddler', 'RIDDLER_USERNAME')
	RIDDLER_PASSWORD = parser.get('Riddler', 'RIDDLER_PASSWORD')

	if RIDDLER_USERNAME == "" or RIDDLER_PASSWORD == "":
		print "  \__", colored("No Riddler API credentials found :(", 'red')
		return []

	else:
		auth = {"email": RIDDLER_USERNAME, "password": RIDDLER_PASSWORD}
		auth_url = "https://riddler.io/auth/login"
		headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0', "content-type": "application/json"}

		try:
			auth_response = requests.post(auth_url, json=auth, headers=headers)
			auth_response_json = loads(auth_response.content)

			if auth_response_json["meta"]["code"] == 200:
				auth_token = auth_response_json["response"]["user"]["authentication_token"]
				search = {"query": "pld:{0}".format(quote(domain)), "output": "host"}
				search_url = "https://riddler.io/api/search"
				headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0', "content-type": "application/json", "authentication-token": auth_token}

				search_response = requests.post(search_url, json=search, headers=headers)
				search_response_json = loads(search_response.content)

				for item in search_response_json:
					riddler.append(item["host"])

				riddler = set(riddler)

				print "  \__", colored("Unique subdomains found:", 'cyan'), colored(len(riddler), 'yellow')
				return riddler

			else:
				print "  \__", colored("Invalid Riddler API credentials :(", 'red')
				return []

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
