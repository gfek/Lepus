import requests
from termcolor import colored
from ConfigParser import SafeConfigParser


def init(domain):
	C = []

	print colored("[*]-Searching Censys...", "yellow")

	parser = SafeConfigParser()
	parser.read("config.ini")
	API_URL = "https://www.censys.io/api/v1"
	UID = parser.get("Censys", "CENSYS_UID")
	SECRET = parser.get("Censys", "CENSYS_SECRET")

	if UID == "" or SECRET == "":
		print "  \__", colored("No Censys API credentials configured", "red")
		return []

	else:
		payload = {"query": domain}

		try:
			res = requests.post(API_URL + "/search/certificates", json=payload, auth=(UID, SECRET))
			payload = res.json()["results"]

			for r in payload:
				str = r["parsed.subject_dn"]
				str1 = str.split("CN=")[1]
				str1 = str1.split(",")

				if domain in str1[0] and not "".join(str1[0]).startswith("*"):
					C.append("".join(str1[0]))

			C = set(C)

			print "  \__", colored("Unique subdomains found:", "cyan"), colored(len(C), "yellow")
			return C

		except KeyError:
			return []

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
