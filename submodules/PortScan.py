from os.path import join
from termcolor import colored
import utilities.MiscHelpers
import utilities.ScanHelpers


def init(domain, resolved, IPs, port_scan, threads):
	targets = []

	if not port_scan:
		port_scan = "medium"

	if port_scan == "small":
		ports = [80, 443]

	elif port_scan == "medium":
		ports = [80, 443, 8000, 8080, 8443]

	elif port_scan == "large":
		ports = [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 9000, 9090, 9443]

	elif port_scan == "huge":
		ports = [80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9943, 9980, 9981, 12443, 16080, 18091, 18092, 20720, 28017]

	else:
		ports = [int(port.strip()) for port in port_scan.split(",")]

	for ip in IPs:
		for port in ports:
			targets.append((ip, port))

	results = utilities.ScanHelpers.massConnectScan(IPs, targets, threads)
	results_json = {}

	for result in results:
		if result[0] in results_json:
			results_json[result[0]].append(result[1])

		else:
			results_json[result[0]] = []
			results_json[result[0]].append(result[1])

	print("    \__ {0}: {1}".format(colored("Open ports that were identified", "yellow"), colored(len(results), "cyan")))
	items = list(results_json.items())

	for key, values in items:
		if key == items[-1][0]:
			print("    __\__ {0}: {1}".format(colored(key, "cyan"), ", ".join(colored(str(value), "yellow") for value in sorted(values))))
			print("   \\")

		else:
			print("      \__ {0}: {1}".format(colored(key, "cyan"), ", ".join(colored(str(value), "yellow") for value in sorted(values))))

	urls = []

	for target in results:
		urls += utilities.MiscHelpers.urlize(target, resolved)

	print("    \__ {0}: {1}".format(colored("URLs that were generated", "yellow"), colored(len(urls), "cyan")))

	for url in sorted(urls):
		print("      \__ {0}".format(colored(url, "cyan")))

	try:
		with open(join("results", domain, "urls.txt"), "w") as port_scan_file:
			for url in sorted(urls):
				port_scan_file.write("{0}\n".format(url))

	except OSError:
		pass

	except IOError:
		pass
