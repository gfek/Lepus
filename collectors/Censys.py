import requests
from re import findall
from json import loads
from termcolor import colored
from configparser import RawConfigParser

def init(domain):
	C = []

	print(colored("[*]-Searching Censys...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	API_URL = "https://search.censys.io/api/v2"
	UID = parser.get("Censys", "CENSYS_UID")
	SECRET = parser.get("Censys", "CENSYS_SECRET")

	if UID == "" or SECRET == "":
		print("  \__", colored("No Censys API credentials configured", "red"))
		return []

	else:
		try:
			res = requests.get(API_URL + "/certificates/search?per_page=99&q={0}".format(domain), auth=(UID, SECRET))
			newres = res.content.decode()

			if res.status_code == 429:
				print("  \__", colored("Rate limit exceeded. See https://www.censys.io/account for rate limit details.", "red"))
				return C
			if res.status_code == 403:
				print("  \__", colored(newres, "red"))
				return C				
			
			C = findall("CN=([\w\d][\w\d\-\.]*\.{0})".format(domain.replace(".", "\.")), newres)	
			nextPage = findall("next\":\s\"((?:[A-Za-z0-9+]{4})*(?:[A-Za-z0-9+]{2}==|[A-Za-z0-9+]{3}=)?)\"", newres)
			if nextPage:
				while nextPage[0]:
					res = requests.get(API_URL + "/certificates/search?per_page=99&q={0}&cursor={1}".format(domain,nextPage[0]), auth=(UID, SECRET))
					if res.status_code == 429:
						print("  \__", colored("Rate limit exceeded. See https://www.censys.io/account for rate limit details.", "red"))
					if res.status_code == 403:
						print("  \__", colored(newres, "red"))						
					newres = res.content.decode()
					tempC = findall("CN=([\w\d][\w\d\-\.]*\.{0})".format(domain.replace(".", "\.")), newres)
					nextPage = findall("next\":\s\"((?:[A-Za-z0-9+]{4})*(?:[A-Za-z0-9+]{2}==|[A-Za-z0-9+]{3}=)?)\"", newres)
					C = C + tempC
		
			C = set(C)

			print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(C), "yellow")))
			return C

		except KeyError as errk:
			print("  \__", colored(errk, "red"))
			return []

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
