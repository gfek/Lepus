from json import dumps
from os.path import join
from termcolor import colored
from ipaddress import ip_network
import utilities.MiscHelpers
import utilities.ScanHelpers


def init(domain, ranges, resolved_public, IPs, threads, out_to_json):
	if ranges:
		IPs = []

		for cidr in ranges.split(","):
			for ip in ip_network(str(cidr.strip())):
				IPs.append(str(ip))

	results = utilities.ScanHelpers.massReverseLookup(IPs, threads)
	filtered = utilities.MiscHelpers.filterDomain(domain, [result[0] for result in results])
	diff = []

	for result in results:
		if result[0] in filtered:
			if result[0] not in resolved_public:
				resolved_public[result[0]] = result[1]
				diff.append(result)

	print("    \__ {0} {1}".format(colored("Additional hostnames that were identified:", "yellow"), colored(len(diff), "cyan")))

	for hostname, address in diff:
		print("      \__ {0} ({1})".format(colored(hostname, "cyan"), colored(address, "yellow")))

	if out_to_json:
		try:
			with open(join("results", domain, "resolved_public.json"), "w") as resolved_public_file:
				resolved_public_file.write("{0}\n".format(dumps(resolved_public)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "resolved_public.csv"), "w") as resolved_public_file:
			for hostname, address in list(resolved_public.items()):
				resolved_public_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	return resolved_public
