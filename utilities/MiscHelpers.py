from termcolor import colored
from ipaddress import ip_network
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import FlushError
from utilities.DatabaseHelpers import Resolution, Unresolved, URL

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


def loadOldFindings(db, domain):
	old_resolved = set()
	old_unresolved = set()

	print(colored("\n[*]-Loading Old Findings...", "yellow"))

	for row in db.query(Resolution).filter(Resolution.domain == domain):
		old_resolved.add(row.subdomain)

	for row in db.query(Unresolved).filter(Unresolved.domain == domain):
		old_unresolved.add(row.subdomain)

	print("  \__ {0}: {1}".format(colored("Subdomains loaded", "cyan"), colored(len(old_resolved) + len(old_unresolved), "yellow")))

	return old_resolved, old_unresolved


def loadWordlist(domain, wordlist):
	print(colored("\n[*]-Loading Wordlist...", "yellow"))

	WL = set([subdomain.strip().lower()for subdomain in wordlist.readlines()])
	wordlist.close()

	print("  \__ {0}: {1}".format(colored("Subdomains loaded", "cyan"), colored(len(WL), "yellow")))
	return WL


def cleanupFindings(domain, old_resolved, old_unresolved, zt, collectors, wordlist):
	unique_subdomains = set()
	findings = [("", "Collectors")]

	if old_resolved:
		for subdomain in old_resolved:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Previously Resolved"))

	if old_unresolved:
		for subdomain in old_unresolved:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Previously Unresolved"))

	if zt:
		for subdomain in zt:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Zone Transfer"))

	if collectors:
		collectors = filterDomain(domain, collectors)

		for subdomain in collectors:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Collectors"))

	if wordlist:
		for subdomain in wordlist:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Wordlist"))

	return findings


def uniqueSubdomainLevels(subdomains):
	unique_subs = set()
	unique_subs.add("")

	for subdomain in subdomains:
		subdomain_parts = subdomain[0].split(".")

		for i in range(len(subdomain_parts) - 1):
			unique_subs.add(".".join(sub for sub in subdomain[0].split(".")[i + 1:]))

	return list(unique_subs)


def filterDomain(domain, subdomains):
	domain_parts = domain.split(".")
	filtered = []

	for subdomain in subdomains:
		subdomain_parts = subdomain.split(".")

		if domain_parts == subdomain_parts[-1 * len(domain_parts):]:
			filtered_subdomain = ".".join(subdomain_parts[:-1 * len(domain_parts)])

			if filtered_subdomain:
				filtered.append(filtered_subdomain)

	return filtered


def chunkify(original, numberOfItemsInChunk):
	for i in range(0, len(original), numberOfItemsInChunk):
		yield original[i:i + numberOfItemsInChunk]


def generateURLs(db, domain, portscan, timestamp):
	for address, ports in portscan.items():
		for row in db.query(Resolution).filter(Resolution.domain == domain):
			if row.subdomain:
				hostname = ".".join([row.subdomain, domain])

			else:
				hostname = domain

			if address == row.address:
				for port in ports:
					if port[0] == 80:
						url = "http://{0}/".format(hostname)

					elif port[0] == 443:
						url = "https://{0}/".format(hostname)

					else:
						if port[1]:
							url = "https://{0}:{1}/".format(hostname, port[0])

						else:
							url = "http://{0}:{1}/".format(hostname, port[0])

					db.add(URL(url=url, domain=domain, timestamp=timestamp))

					try:
						db.commit()

					except (IntegrityError, FlushError):
						db.rollback()
