from slack import WebClient
from datetime import datetime
from termcolor import colored
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import FlushError
from ipaddress import ip_address, ip_network
from os import makedirs, listdir, stat, remove
from utilities.DatabaseHelpers import Record, Wildcard, Resolution, Unresolved, ASN, Network, OpenPort, URL, Takeover


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
	old_takeovers = set()

	print(colored("\n[*]-Loading Old Findings...", "yellow"))

	for row in db.query(Resolution).filter(Resolution.domain == domain):
		old_resolved.add((row.subdomain, row.source))

	for row in db.query(Unresolved).filter(Unresolved.domain == domain):
		old_unresolved.add(row.subdomain)

	for row in db.query(Takeover).filter(Takeover.domain == domain):
		old_takeovers.add(".".join([row.subdomain, domain]))

	print("  \__ {0}: {1}".format(colored("Subdomains loaded", "cyan"), colored(len(old_resolved) + len(old_unresolved), "yellow")))
	return old_resolved, old_unresolved, old_takeovers


def purgeOldFindings(db, domain):
	db.query(Wildcard).filter(Wildcard.domain == domain).delete()
	db.commit()

	db.query(Resolution).filter(Resolution.domain == domain).delete()
	db.commit()

	db.query(Unresolved).filter(Unresolved.domain == domain).delete()
	db.commit()

	db.query(ASN).filter(ASN.domain == domain).delete()
	db.commit()

	db.query(Network).filter(Network.domain == domain).delete()
	db.commit()

	db.query(OpenPort).filter(OpenPort.domain == domain).delete()
	db.commit()

	db.query(URL).filter(URL.domain == domain).delete()
	db.commit()

	db.query(Takeover).filter(Takeover.domain == domain).delete()
	db.commit()

	db.query(Record).filter(Record.domain == domain).delete()
	db.commit()

	db.execute("VACUUM;")


def loadWordlist(domain, wordlist):
	print(colored("\n[*]-Loading Wordlist...", "yellow"))

	WL = set([subdomain.strip().lower()for subdomain in wordlist.readlines()])
	wordlist.close()

	print("  \__ {0}: {1}".format(colored("Subdomains loaded", "cyan"), colored(len(WL), "yellow")))
	return WL


def cleanupFindings(domain, old_resolved, old_unresolved, zt, collectors, wordlist):
	unique_subdomains = set()
	findings = [("", "Collectors")]

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

	if old_resolved:
		for item in old_resolved:
			subdomain = item[0].lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, item[1]))

	if old_unresolved:
		for subdomain in old_unresolved:
			subdomain = subdomain.lower()

			if subdomain not in unique_subdomains:
				unique_subdomains.add(subdomain)
				findings.append((subdomain, "Collectors"))

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
		for row in db.query(Resolution).filter(Resolution.domain == domain, Resolution.address == address):
			if row.subdomain:
				hostname = ".".join([row.subdomain, domain])

			else:
				hostname = domain

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


def slackNotification(token, channel, text):
	client = WebClient(token=token)
	client.chat_postMessage(channel=channel, text=text, username="Lepus", icon_emoji=":rabbit2:")


def exportFindings(db, domain, old_resolved, interrupt):
	if interrupt:
		print(colored("\n[*]-Exporting what has been found so far...", "red"))
	else:
		print(colored("\n[*]-Exporting findings...", "yellow"))

	old_hostnames = [items[0] for items in old_resolved]
	path = "findings/{0}".format(domain)
	makedirs(path, exist_ok=True)

	with open("{0}/{1}".format(path, "records.csv"), "w") as records:
		for row in db.query(Record).filter(Record.domain == domain).order_by(Record.type):
			records.write("{0}|{1}\n".format(row.type, row.value))

	with open("{0}/{1}".format(path, "resolved_public.csv"), "w") as resolved_public:
		with open("{0}/{1}".format(path, "resolved_private.csv"), "w") as resolved_private:
			with open("{0}/{1}".format(path, "resolved_ipv6.csv"), "w") as resolved_ipv6:
				with open("{0}/{1}".format(path, "diff.log"), "a") as diff:
					new = True

					for row1 in db.query(Resolution.subdomain).filter(Resolution.domain == domain).order_by(Resolution.subdomain).distinct():
						diff_list = []
						public = []
						private = []
						ipv6 = []

						for row2 in db.query(Resolution.address).filter(Resolution.domain == domain, Resolution.subdomain == row1.subdomain).order_by(Resolution.address):
							if old_hostnames:
								if row1.subdomain not in old_hostnames:
									diff_list.append(row2.address)

							if ":" in row2.address:
								ipv6.append(row2.address)

							else:
								if ip_address(row2.address).is_private:
									private.append(row2.address)

								elif ip_address(row2.address).is_global:
									public.append(row2.address)

						if diff_list:
							if new:
								diff.write("\n[!] {0}\n".format(datetime.now()))
								new = False

							if row1.subdomain == "":
								diff.write("  \__ {0}: {1}\n".format(domain, ", ".join(diff_list)))

							else:
								diff.write("  \__ {0}.{1}: {2}\n".format(row1.subdomain, domain, ", ".join(diff_list)))

						if ipv6:
							if row1.subdomain == "":
								resolved_ipv6.write("{0}|{1}\n".format(domain, ",".join(ipv6)))

							else:
								resolved_ipv6.write("{0}.{1}|{2}\n".format(row1.subdomain, domain, ",".join(ipv6)))

						if private:
							if row1.subdomain == "":
								resolved_private.write("{0}|{1}\n".format(domain, ",".join(private)))

							else:
								resolved_private.write("{0}.{1}|{2}\n".format(row1.subdomain, domain, ",".join(private)))

						if public:
							if row1.subdomain == "":
								resolved_public.write("{0}|{1}\n".format(domain, ",".join(public)))

							else:
								resolved_public.write("{0}.{1}|{2}\n".format(row1.subdomain, domain, ",".join(public)))

	with open("{0}/{1}".format(path, "unresolved.csv"), "w") as unresolved:
		for row in db.query(Unresolved.subdomain).filter(Unresolved.domain == domain).order_by(Unresolved.subdomain):
			unresolved.write("{0}.{1}\n".format(row.subdomain, domain))

	with open("{0}/{1}".format(path, "wildcards.csv"), "w") as wildcards:
		for row in db.query(Wildcard).filter(Wildcard.domain == domain).order_by(Wildcard.subdomain):
			wildcards.write("{0}.{1}|{2}\n".format(row.subdomain, domain, row.address))

	with open("{0}/{1}".format(path, "asn.csv"), "w") as asn:
		for row in db.query(ASN).filter(ASN.domain == domain).order_by(ASN.id):
			asn.write("{0}|{1}|{2}\n".format(row.id, row.prefix, row.description))

	with open("{0}/{1}".format(path, "networks.csv"), "w") as networks:
		for row in db.query(Network).filter(Network.domain == domain).order_by(Network.cidr):
			networks.write("{0}|{1}|{2}\n".format(row.cidr, row.identifier, row.country))

	with open("{0}/{1}".format(path, "open_ports.csv"), "w") as open_ports:
		for row1 in db.query(OpenPort.address).order_by(OpenPort.address).distinct():
			open_ports.write("{0}|{1}\n".format(row1.address, ",".join([str(row2.port) for row2 in db.query(OpenPort.port).filter(OpenPort.domain == domain, OpenPort.address == row1.address).order_by(OpenPort.port)])))

	with open("{0}/{1}".format(path, "urls.csv"), "w") as urls:
		for row in db.query(URL.url).filter(URL.domain == domain):
			urls.write("{0}\n".format(row.url))

	with open("{0}/{1}".format(path, "takeovers.csv"), "w") as takeovers:
		for row in db.query(Takeover).filter(Takeover.domain == domain).order_by(Takeover.subdomain):
			takeovers.write("{0}.{1}|{2}|{3}\n".format(row.subdomain, domain, row.provider, row.signature))

	for exported_file in listdir(path):
		if stat("{0}/{1}".format(path, exported_file)).st_size == 0:
			remove("{0}/{1}".format(path, exported_file))

	print("  \__ {0}!\n".format(colored("Done", "cyan")))
