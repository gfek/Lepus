import shodan
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
	SD = []

	print(colored("[*]-Searching Shodan...", "yellow"))

	parser = RawConfigParser()
	parser.read("config.ini")
	SHODAN_API_KEY = parser.get("Shodan", "SHODAN_API_KEY")
	api = shodan.Shodan(SHODAN_API_KEY)

	if SHODAN_API_KEY == "":
		print("  \__", colored("No Shodan API key configured", "red"))
		return []

	else:
		try:
			results = api.search("hostname:.{0}".format(domain))

			try:
				for res in results["matches"]:
					SD.append("".join(res["hostnames"]))

			except KeyError as errk:
				print("  \__", colored(errk, "red"))
				return []

			SD = set(SD)

			print("  \__ {0}: {1}".format(colored("Unique subdomains found", "cyan"), colored(len(SD), "yellow")))
			return SD

		except shodan.exception.APIError as err:
			print("  \__", colored(err, "red"))
			return []

		except Exception:
			print("  \__", colored("Something went wrong!", "red"))
			return []
