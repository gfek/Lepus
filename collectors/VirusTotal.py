import requests
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	VT = []

	print(colored("[*]-Searching VirusTotal...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	VT_API_KEY = parser.get("VirusTotal", "VT_API_KEY")

	if VT_API_KEY == "":
		print("  \__", colored("No VirusTotal API key configured", "red"))
		return []

	else:
		parameters = {"domain": domain, "apikey": VT_API_KEY}
		headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0"}

		try:
			response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=parameters, headers=headers)
			response_dict = response.json()

			if "subdomains" in response_dict:
				for sd in response_dict["subdomains"]:
					VT.append(sd)

			VT = set(VT)

			print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(VT), "yellow")))
			return VT

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
