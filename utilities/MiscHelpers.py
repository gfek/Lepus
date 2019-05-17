from json import dumps
from time import time, ctime
from termcolor import colored
from ipaddress import ip_network
from os.path import exists, isfile, join
from os import makedirs, listdir, stat, remove


def checkArgumentValidity(parser, args):
	if args.permutation_wordlist and not args.permutate and args.permutation_wordlist.name != "lists/words.txt":
		parser.print_usage()
		print("lepus.py: error: argument -pw/--permutation-wordlist: missing required argument '--permutate'")
		return False

	if args.ranges and not args.reverse:
		parser.print_usage()
		print("lepus.py: error: argument -r/--ranges: missing required argument '--reverse'")
		return False

	if args.ranges:
		try:
			for cidr in args.ranges.split(","):
				ip_network(str(cidr))

		except Exception:
			parser.print_usage()
			print("lepus.py: error: argument -r/--ranges: invalid ip range: '{0}' ".format(cidr))
			return False

	if args.ports and not args.portscan:
		parser.print_usage()
		print("lepus.py: error: argument -p/--ports: missing required argument '--portscan'")
		return False

	if args.ports:
		if args.ports not in ["small", "medium", "large", "huge"]:
			try:
				ports = [int(port.strip()) for port in args.ports.split(",")]

				for port in ports:
					if port < 0 or port > 65535:
						parser.print_usage()
						print("lepus.py: error: argument -p/--ports: invalid port: '{0}' ".format(port))
						return False

			except Exception:
				parser.print_usage()
				print("lepus.py: error: argument -p/--ports: invalid set of ports: '{0}'".format(args.ports))
				return False

	return True


def deleteEmptyFiles(directory):
	try:
		filenames = [filename for filename in listdir(join("results", directory)) if isfile(join("results", directory, filename))]

		for filename in filenames:
			if stat(join("results", directory, filename)).st_size == 0:
				remove(join("results", directory, filename))

	except OSError:
		pass


def diffLastRun(domain, wildcards, resolved_public, old_resolved_public, last_run, current_run):
	diff = {}

	for host, ip in list(resolved_public.items()):
		if host not in old_resolved_public:
			diff[host] = ip

	if diff:
		print("{0} {1}:".format(colored("\n[*]-Differences since", "yellow"), colored(ctime(int(last_run)), "cyan")))

		for host, ip in list(diff.items()):
			if ip in wildcards:
				actual_wildcard = False

				for value in wildcards[ip]:
					if value in host:
						actual_wildcard = True

				if actual_wildcard:
					print("  \__ {0} ({1})".format(colored(host, "cyan"), colored(ip, "red")))

				else:
					print("  \__ {0} ({1})".format(colored(host, "cyan"), colored(ip, "yellow")))

			else:
				print("  \__ {0} ({1})".format(colored(host, "cyan"), colored(ip, "yellow")))

		try:
			if exists(join("results", domain, "diff.log")):
				initialDiff = False

			else:
				initialDiff = True

			with open(join("results", domain, "diff.log"), "a") as diff_file:
				if initialDiff:
					diff_file.write("# ---------- {0} ---------- #\n".format(ctime(int(current_run))))

				else:
					diff_file.write("\n# ---------- {0} ---------- #\n".format(ctime(int(current_run))))

				diff_file.write("[!] Differences since {0}\n".format(ctime(int(last_run))))

				for host, ip in list(diff.items()):
					diff_file.write("  \__ {0} ({1})\n".format(host, ip))

		except OSError:
			pass

		except IOError:
			pass


def createWorkspace(directory):
	dir_path = join("results", directory)

	if not exists(dir_path):
		makedirs(dir_path)

		return True

	else:
		return False


def saveCollectorResults(domain, subdomains):
	if subdomains:
		try:
			with open(join("results", domain, "passive_findings.txt"), "w") as collector_file:
				for subdomain in subdomains:
					collector_file.write("{0}\n".format(subdomain))

		except OSError:
			pass

		except IOError:
			pass


def loadOldFindings(directory):
	filenames = [filename for filename in listdir(join("results", directory)) if isfile(join("results", directory, filename))]
	OF = []
	ORP = []
	collector_results = []

	print(colored("\n[*]-Loading Old Findings...", "yellow"))

	for filename in filenames:
		if "resolved" in filename:
			try:
				with open(join("results", directory, filename), "r") as old_file:
					lines = old_file.readlines()

					for line in lines:
						OF.append(line.split("|")[0])

						if "public" in filename:
							ORP.append(line.split("|")[0])

			except OSError:
				pass

			except IOError:
				pass

		if filename == ".timestamp":
			with open(join("results", directory, filename), "r") as timestamp_file:
				last_run = timestamp_file.read()

		if filename == "passive_findings.txt":
			with open(join("results", directory, filename), "r") as collector_file:
				collector_results += [line.strip() for line in collector_file.readlines()]

	print("  \__ {0}: {1}".format(colored("Unique subdomains loaded", "cyan"), colored(len(OF), "yellow")))
	return OF, ORP, last_run, collector_results


def loadWordlist(domain, wordlist):
	print(colored("\n[*]-Loading Wordlist...", "yellow"))

	WL = set([".".join([subdomain.strip().lower(), domain]) for subdomain in wordlist.readlines()])
	wordlist.close()

	print("  \__ {0}: {1}".format(colored("Unique subdomains loaded", "cyan"), colored(len(WL), "yellow")))
	return list(WL)


def uniqueSubdomainLevels(hosts):
	unique_subs = set()

	for host in hosts:
		unique_subs.add(".".join(sub for sub in host.split(".")[1:]))

	return list(unique_subs)


def uniqueList(subdomains):
	uniqe_subdomains = set()

	for subdomain in subdomains:
		uniqe_subdomains.add(subdomain.lower())

	return list(uniqe_subdomains)


def filterDomain(domain, subdomains):
	domain_parts = domain.split(".")
	filtered = []

	for subdomain in subdomains:
		subdomain_parts = subdomain.split(".")

		if domain_parts == subdomain_parts[-1 * len(domain_parts):]:
			filtered.append(subdomain)

	return filtered


def chunks(list, numberInChunk):
	for i in range(0, len(list), numberInChunk):
		yield list[i:i + numberInChunk]


def urlize(target, domains):
	hosts = [hostname for hostname, address in list(domains.items()) if address == target[0]]
	urls = []

	for host in hosts:
		if target[1] == 80:
			urls.append("http://{0}/".format(host))

		elif target[1] == 443:
			urls.append("https://{0}/".format(host))

		else:
			if target[2]:
				urls.append("https://{0}:{1}/".format(host, target[1]))

			else:
				urls.append("http://{0}:{1}/".format(host, target[1]))

	return urls
