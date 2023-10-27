import requests
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	RHL = []

	print(colored("[*]-Searching RedHunt Labs API...", "red"))

	parser = RawConfigParser()
	parser.read("config.ini")
	X_BLOBR_KEY = parser.get("RedHuntLabs", "X_BLOBR_KEY")

	if X_BLOBR_KEY == "":
		print("  \__", colored("No RedHunt Labs API key configured", "red"))
		return []

	else:
		headers = {"X-BLOBR-KEY": X_BLOBR_KEY}
		page = 1
		
		while 1:
			try:
				response = requests.get('https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={domain}&page_size=10&page={page}', headers=headers)

				if response.status_code == 200:
					response_data = response.json()
					if response_data['subdomains']:
						for sub in response_data['subdomains']: 
							RHL.append(sub)
							page+=1

				else:
					error_message = response.json()['message']
					if "limit has been reached" in error_message:
						print ("Your API credits have been exhausted. Head over to https://devportal.redhuntlabs.com/")
					page = False

				RHL = set(RHL)

				print("  \__ {0}: {1}".format(colored("Subdomains found", "cyan"), colored(len(RHL), "yellow")))
				return RHL

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
