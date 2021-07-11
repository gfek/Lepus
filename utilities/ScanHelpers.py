from time import time
from tqdm import tqdm
from gc import collect
from sys import stderr,stdout
from dns.query import xfr
from ipwhois import IPWhois
from dns.zone import from_xfr
from termcolor import colored
from ipaddress import ip_address
from dns.resolver import Resolver
from collections import OrderedDict
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import FlushError
from ssl import create_default_context, CERT_NONE
from concurrent.futures import ThreadPoolExecutor, as_completed
from socket import getaddrinfo, gethostbyaddr, socket, AF_INET, AF_INET6, SOCK_STREAM
from utilities.DatabaseHelpers import Record, Wildcard, Resolution, Unresolved, ASN, Network, OpenPort
import utilities.MiscHelpers


def zoneTransfer(db, domain):
	print(colored("\n[*]-Attempting to zone transfer from the identified nameservers...", "yellow"))

	for row in db.query(Record).filter(Record.domain == domain, Record.type == "NS"):
		try:
			zone = from_xfr(xfr(row.value, domain))
			subdomains = set([str(key) for key in zone.nodes.keys()])

			print("  \__ {0}: {1}".format(colored("Subdomains retrieved", "cyan"), colored(len(subdomains), "yellow")))
			return subdomains

		except Exception:
			continue

	print("  \__", colored("Failed to zone transfer.", "red"))
	return None


def retrieveDNSRecords(db, domain):
	resolver = Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1
	types = ["A", "MX", "NS", "AAAA", "SOA", "TXT"]
	timestamp = int(time())

	print(colored("\n[*]-Retrieving DNS Records...", "yellow"))

	for type in types:
		try:
			answers = resolver.query(domain, type)

			for answer in answers:
				if type == "A":
					db.add(Record(domain=domain, type=type, value=answer.address, timestamp=timestamp))

				if type == "MX":
					db.add(Record(domain=domain, type=type, value=answer.exchange.to_text()[:-1], timestamp=timestamp))

				if type == "NS":
					db.add(Record(domain=domain, type=type, value=answer.target.to_text()[:-1], timestamp=timestamp))

				if type == "AAAA":
					db.add(Record(domain=domain, type=type, value=answer.address, timestamp=timestamp))

				if type == "SOA":
					db.add(Record(domain=domain, type=type, value=answer.mname.to_text()[:-1], timestamp=timestamp))

				if type == "TXT":
					db.add(Record(domain=domain, type=type, value=str(answer), timestamp=timestamp))

				try:
					db.commit()

				except (IntegrityError, FlushError):
					db.rollback()

		except Exception as e:
			pass

	for row in db.query(Record).filter(Record.domain == domain).order_by(Record.type):
		print("  \__ {0}: {1}".format(colored(row.type, "cyan"), colored(row.value, "yellow")))


def checkWildcard(timestamp, subdomain, domain):
	try:
		if subdomain:
			return (subdomain, [item[4][0] for item in getaddrinfo(".".join([timestamp, subdomain, domain]), None)])

		else:
			return (subdomain, [item[4][0] for item in getaddrinfo(".".join([timestamp, domain]), None)])

	except Exception:
		return (subdomain, None)


def identifyWildcards(db, findings, domain, threads):
	if len(findings) <= 10000:
		print(colored("\n[*]-Generating samples for wildcard identification...", "yellow"))
	
	else:
		print(colored("\n[*]-Generating samples for wildcard identification in chunks of 10,000...", "yellow"))

	numberOfFindingsChunks = len(findings) // 10000 + 1
	findingsChunks = utilities.MiscHelpers.chunkify(findings, 10000)
	findingsChunkIterator = 1

	timestamp = int(time())
	wildcards = set()
	optimized_wildcards = {}
	new_wildcards = OrderedDict()

	for findingsChunk in findingsChunks:
		sub_levels = utilities.MiscHelpers.uniqueSubdomainLevels(findingsChunk)
		numberOfChunks = len(sub_levels) // 100000 + 1
		leaveFlag = False

		print("  \__ {0} {1}".format(colored("Checking for wildcards for chunk", "yellow"), colored(str(findingsChunkIterator) + "/" + str(numberOfFindingsChunks), "cyan")))

		subLevelChunks = utilities.MiscHelpers.chunkify(sub_levels, 100000)
		iteration = 1

		del sub_levels
		collect()

		for subLevelChunk in subLevelChunks:
			with ThreadPoolExecutor(max_workers=threads) as executor:
				tasks = {executor.submit(checkWildcard, str(timestamp), sub_level, domain) for sub_level in subLevelChunk}

				try:
					completed = as_completed(tasks)

					if iteration == numberOfChunks:
						leaveFlag = True

					if numberOfChunks == 1:
						completed = tqdm(completed, total=len(subLevelChunk), desc="    \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

					else:
						completed = tqdm(completed, total=len(subLevelChunk), desc="    \__ {0}".format(colored("Progress {0}/{1}".format(iteration, numberOfChunks), "cyan")), dynamic_ncols=True, leave=leaveFlag)

					for task in completed:
						result = task.result()

						if result[1] is not None:
							for address in result[1]:
								wildcards.add((".".join([result[0], domain]), address))

				except KeyboardInterrupt:
					completed.close()
					print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
					utilities.MiscHelpers.exportFindings(db, domain, [], True)
					executor.shutdown(wait=False)
					exit(-1)

			if iteration < numberOfChunks:
				stderr.write("\033[F")

			iteration += 1
		
		if findingsChunkIterator < numberOfFindingsChunks:
			stdout.write("\033[F\033[F")
		
		findingsChunkIterator += 1

	if wildcards:
		reversed_wildcards = [(".".join(reversed(hostname.split("."))).rstrip("."), ip) for hostname, ip in wildcards]
		sorted_wildcards = sorted(reversed_wildcards, key=lambda rw: rw[0])

		for reversed_hostname, ip in sorted_wildcards:
			if reversed_hostname == reversed(domain):
				hostname = domain

			else:
				hostname = ".".join(reversed(reversed_hostname.split(".")))

			new_wildcard = True

			if ip in optimized_wildcards:
				for entry in optimized_wildcards[ip]:
					if len(hostname.split(".")) > len(entry.split(".")):
						if entry in hostname:
							new_wildcard = False

				if new_wildcard:
					optimized_wildcards[ip].append(hostname)

			else:
				optimized_wildcards[ip] = [hostname]

		del wildcards
		del reversed_wildcards
		del sorted_wildcards
		collect()

		for address, hostnames in list(optimized_wildcards.items()):
			for hostname in hostnames:
				if hostname == domain:
					db.add(Wildcard(subdomain="", domain=domain, address=address, timestamp=timestamp))

				else:
					db.add(Wildcard(subdomain=".".join(hostname.split(".")[:-1 * len(domain.split("."))]), domain=domain, address=address, timestamp=timestamp))

				try:
					db.commit()

				except (IntegrityError, FlushError):
					db.rollback()

		del optimized_wildcards
		collect()

		for row in db.query(Wildcard).filter(Wildcard.domain == domain, Wildcard.timestamp == timestamp).order_by(Wildcard.subdomain):
			if row.subdomain:
				hostname = ".".join([row.subdomain, domain])

			else:
				hostname = domain

			if hostname in new_wildcards:
				new_wildcards[hostname].append(row.address)

			else:
				new_wildcards[hostname] = []
				new_wildcards[hostname].append(row.address)

		print("    \__ {0}: {1}".format(colored("New wildcards that were identified", "yellow"), colored(len(new_wildcards.items()), "cyan")))

		for hostname, addresses in new_wildcards.items():
			print("      \__ {0}.{1} ==> {2}".format(colored("*", "red"), colored(hostname, "cyan"), ", ".join([colored(address, "red") for address in addresses])))


def resolve(finding, domain):
	try:
		if finding[0]:
			return (finding[0], [item[4][0] for item in getaddrinfo(".".join([finding[0], domain]), None)], finding[1])

		else:
			return (finding[0], [item[4][0] for item in getaddrinfo(domain, None)], finding[1])

	except Exception:
		return (finding[0], None, finding[1])


def massResolve(db, findings, domain, hideWildcards, threads):
	resolved = set()
	unresolved = set()
	wildcards = {}
	new_resolutions = OrderedDict()
	timestamp = int(time())
	numberOfChunks = 1
	leaveFlag = False

	for row in db.query(Wildcard).filter(Wildcard.domain == domain):
		if row.subdomain:
			hostname = ".".join([row.subdomain, domain])

		else:
			hostname = domain

		if hostname in wildcards:
			wildcards[hostname].append(row.address)

		else:
			wildcards[hostname] = []
			wildcards[hostname].append(row.address)

	if len(findings) <= 100000:
		print("{0} {1} {2}".format(colored("\n[*]-Attempting to resolve", "yellow"), colored(len(findings), "cyan"), colored("hostnames...", "yellow")))

	else:
		print("{0} {1} {2}".format(colored("\n[*]-Attempting to resolve", "yellow"), colored(len(findings), "cyan"), colored("hostnames, in chunks of 100,000...", "yellow")))
		numberOfChunks = len(findings) // 100000 + 1

	findingsChunks = utilities.MiscHelpers.chunkify(findings, 100000)
	iteration = 1

	for findingsChunk in findingsChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(resolve, finding, domain) for finding in findingsChunk}

			try:
				completed = as_completed(tasks)

				if iteration == numberOfChunks:
					leaveFlag = True

				if numberOfChunks == 1:
					completed = tqdm(completed, total=len(findingsChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				else:
					completed = tqdm(completed, total=len(findingsChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, numberOfChunks), "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					try:
						result = task.result()

						if result[1] is not None:
							for address in result[1]:
								if result[0]:
									resolved.add((".".join([result[0], domain]), address, result[2]))

								else:
									resolved.add((domain, address, result[2]))

						else:
							if result[2] == "Collectors":
								unresolved.add((result[0], domain))

					except Exception:
						continue

			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
				utilities.MiscHelpers.exportFindings(db, domain, [], True)
				executor.shutdown(wait=False)
				exit(-1)

		if iteration < numberOfChunks:
			stderr.write("\033[F")

		iteration += 1

	for hostname, address, source in resolved:
		isWildcard = False

		for wildcard, addresses in wildcards.items():
			if wildcard in hostname:
				if address in addresses:
					isWildcard = True


		if (not isWildcard) or (isWildcard and source == "Collectors"):
			if hostname == domain:
				db.add(Resolution(subdomain="", domain=domain, address=address, isWildcard=isWildcard, source=source, timestamp=timestamp))

			else:
				db.add(Resolution(subdomain=".".join(hostname.split(".")[:-1 * len(domain.split("."))]), domain=domain, address=address, isWildcard=isWildcard, source=source, timestamp=timestamp))

			try:
				db.commit()

			except (IntegrityError, FlushError):
				db.rollback()

	for subdomain, domain in unresolved:
		db.add(Unresolved(subdomain=subdomain, domain=domain, timestamp=timestamp))

		try:
			db.commit()

		except (IntegrityError, FlushError):
			db.rollback()

	del resolved
	del unresolved
	del wildcards
	collect()

	for row in db.query(Resolution).filter(Resolution.domain == domain, Resolution.timestamp == timestamp).order_by(Resolution.subdomain):
		if row.subdomain:
			hostname = ".".join([row.subdomain, domain])

		else:
			hostname = domain

		if row.isWildcard:
			address = colored(row.address, "red")

		else:
			address = colored(row.address, "yellow")

		if (not row.isWildcard) or (row.isWildcard and not hideWildcards):
			if hostname in new_resolutions:
				new_resolutions[hostname].append(address)

			else:
				new_resolutions[hostname] = []
				new_resolutions[hostname].append(address)

	print("    \__ {0}: {1}".format(colored("New hostnames that were resolved", "yellow"), colored(len(new_resolutions.items()), "cyan")))

	for hostname, addresses in new_resolutions.items():
		print("      \__ {0}: {1}".format(colored(hostname, "cyan"), ", ".join([address for address in addresses])))


def reverseLookup(IP):
	try:
		return (gethostbyaddr(IP)[0].lower(), IP)

	except Exception:
		return (None, IP)


def massReverseLookup(db, domain, IPs, threads):
	results = set()
	hostnames = set()
	result_dict = {}
	numberOfChunks = 1
	leaveFlag = False
	timestamp = int(time())
	reverse_resolutions = OrderedDict()

	if len(IPs) <= 100000:
		print("{0} {1} {2}".format(colored("\n[*]-Performing reverse DNS lookups on", "yellow"), colored(len(IPs), "cyan"), colored("public IPs...", "yellow")))

	else:
		print("{0} {1} {2}".format(colored("\n[*]-Performing reverse DNS lookups on", "yellow"), colored(len(IPs), "cyan"), colored("public IPs, in chunks of 100,000...", "yellow")))
		numberOfChunks = len(IPs) // 100000 + 1

	IPChunks = utilities.MiscHelpers.chunkify(IPs, 100000)
	iteration = 1

	del IPs
	collect()

	for IPChunk in IPChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(reverseLookup, IP) for IP in IPChunk}

			try:
				completed = as_completed(tasks)

				if iteration == numberOfChunks:
					leaveFlag = True

				if numberOfChunks == 1:
					completed = tqdm(completed, total=len(IPChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				else:
					completed = tqdm(completed, total=len(IPChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, numberOfChunks), "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					result = task.result()

					if result[0] is not None:
						results.add(result)
						hostnames.add(result[0])


			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
				utilities.MiscHelpers.exportFindings(db, domain, [], True)
				executor.shutdown(wait=False)
				exit(-1)

		if iteration < numberOfChunks:
			stderr.write("\033[F")

		iteration += 1

	filtered_subdomains = utilities.MiscHelpers.filterDomain(domain, hostnames)

	del hostnames
	collect()

	for result in results:
		if result[0] in result_dict:
			result_dict[result[0]].append(result[1])

		else:
			result_dict[result[0]] = []
			result_dict[result[0]].append(result[1])

	del results
	collect()

	for subdomain in filtered_subdomains:
		if subdomain:
			hostname = ".".join([subdomain, domain])

		else:
			hostname = domain

		for address in result_dict[hostname]:
			db.add(Resolution(subdomain=subdomain, domain=domain, address=address, isWildcard=False, source="Reverse", timestamp=timestamp))

			try:
				db.commit()

			except (IntegrityError, FlushError):
				db.rollback()

	del result_dict
	del filtered_subdomains
	collect()

	for row in db.query(Resolution).filter(Resolution.domain == domain, Resolution.timestamp == timestamp).order_by(Resolution.subdomain):
		if row.subdomain:
			hostname = ".".join([row.subdomain, domain])

		else:
			hostname = domain

		address = colored(row.address, "yellow")

		if hostname in reverse_resolutions:
			reverse_resolutions[hostname].append(address)

		else:
			reverse_resolutions[hostname] = []
			reverse_resolutions[hostname].append(address)

	print("    \__ {0}: {1}".format(colored("Additional hostnames that were resolved", "yellow"), colored(len(reverse_resolutions.items()), "cyan")))

	for hostname, addresses in reverse_resolutions.items():
		print("      \__ {0}: {1}".format(colored(hostname, "cyan"), ", ".join([address for address in addresses])))


def connectScan(target):
	isOpen = False

	if "." in target[0]:
		s = socket(AF_INET, SOCK_STREAM)

	else:
		s = socket(AF_INET6, SOCK_STREAM)

	try:
		s.settimeout(1)
		result = s.connect_ex(target)

		if not result:
			if target[1] != 80 and target[1] != 443:
				isOpen = True
				context = create_default_context()
				context.check_hostname = False
				context.verify_mode = CERT_NONE
				context.wrap_socket(s)

				return (target[0], target[1], True)

			elif target[1] == 80:
				return (target[0], target[1], False)

			elif target[1] == 443:
				return (target[0], target[1], True)

	except Exception as e:
		if isOpen:
			if "unsupported protocol" in str(e):
				return (target[0], target[1], True)

			else:
				return (target[0], target[1], False)

		else:
			return None

	finally:
		s.close()


def massConnectScan(db, domain, numberOfUniqueIPs, targets, threads, timestamp):
	open_ports = []
	leaveFlag = False
	numberOfChunks = 1

	if len(targets) <= 100000:
		print("{0} {1} {2} {3} {4}".format(colored("\n[*]-Scanning", "yellow"), colored(len(targets), "cyan"), colored("ports on", "yellow"), colored(numberOfUniqueIPs, "cyan"), colored("public IPs...", "yellow")))

	else:
		print("{0} {1} {2} {3} {4}".format(colored("\n[*]-Scanning", "yellow"), colored(len(targets), "cyan"), colored("ports on", "yellow"), colored(numberOfUniqueIPs, "cyan"), colored("public IPs, in chunks of 100,000...", "yellow")))
		numberOfChunks = len(targets) // 100000 + 1

	PortChunks = utilities.MiscHelpers.chunkify(targets, 100000)
	iteration = 1

	for PortChunk in PortChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(connectScan, target) for target in PortChunk}

			try:
				completed = as_completed(tasks)

				if iteration == numberOfChunks:
					leaveFlag = True

				if numberOfChunks == 1:
					completed = tqdm(completed, total=len(PortChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				else:
					completed = tqdm(completed, total=len(PortChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, numberOfChunks), "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					result = task.result()

					if result is not None:
						open_ports.append(result)

			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
				utilities.MiscHelpers.exportFindings(db, domain, [], True)
				executor.shutdown(wait=False)
				exit(-1)

		if iteration < numberOfChunks:
			stderr.write("\033[F")

		iteration += 1

	for open_port in open_ports:
		db.add(OpenPort(domain=domain, address=open_port[0], port=open_port[1], isSSL=open_port[2], timestamp=timestamp))

		try:
			db.commit()

		except (IntegrityError, FlushError):
			db.rollback()


def rdap(ip):
	try:
		obj = IPWhois(ip)
		result = obj.lookup_rdap()

		return result

	except Exception:
		return {}


def massRDAP(db, domain, threads):
	IPs = set()
	rdap_records = []
	numberOfChunks = 1
	leaveFlag = False
	timestamp = int(time())

	for row in db.query(Resolution).filter(Resolution.domain == domain):
		if "." in row.address:
			if ip_address(row.address).is_global:
				IPs.add(row.address)

		else:
			IPs.add(row.address)

	IPs = list(IPs)

	if len(IPs) <= 100000:
		print("{0} {1} {2}".format(colored("\n[*]-Performing RDAP lookups for", "yellow"), colored(len(IPs), "cyan"), colored("public IPs...", "yellow")))

	else:
		print("{0} {1} {2}".format(colored("\n[*]-Performing RDAP lookups for", "yellow"), colored(len(IPs), "cyan"), colored("public IPs, in chunks of 100,000...", "yellow")))
		numberOfChunks = len(IPs) // 100000 + 1

	IPChunks = utilities.MiscHelpers.chunkify(IPs, 100000)
	iteration = 1

	del IPs
	collect()

	for IPChunk in IPChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(rdap, IP) for IP in IPChunk}

			try:
				completed = as_completed(tasks)

				if iteration == numberOfChunks:
					leaveFlag = True

				if numberOfChunks == 1:
					completed = tqdm(completed, total=len(IPChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				else:
					completed = tqdm(completed, total=len(IPChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, numberOfChunks), "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					result = task.result()

					if result:
						rdap_records.append(result)

			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
				utilities.MiscHelpers.exportFindings(db, domain, [], True)
				executor.shutdown(wait=False)
				exit(-1)

		if iteration < numberOfChunks:
			stderr.write("\033[F")

		iteration += 1

	for record in rdap_records:
		if record["asn"] != "NA" and record["asn_cidr"] != "NA" and record["asn_description"] != "NA":
			for asn in record["asn"].split(" "):
				db.add(ASN(domain=domain, id=asn, prefix=record["asn_cidr"], description=record["asn_description"], timestamp=timestamp))

				try:
					db.commit()

				except (IntegrityError, FlushError):
					db.rollback()

		for cidr in record["network"]["cidr"].split(", "):
			db.add(Network(domain=domain, cidr=cidr, identifier=record["network"]["name"], country=record["asn_country_code"], timestamp=timestamp))

			try:
				db.commit()

			except (IntegrityError, FlushError):
				db.rollback()

	del rdap_records
	collect()

	print("    \__ {0}:".format(colored("New autonomous Systems that were identified", "yellow")))

	for row in db.query(ASN).filter(ASN.domain == domain).order_by(ASN.id, ASN.prefix):
		if row == db.query(ASN).filter(ASN.domain == domain).order_by(ASN.id.desc(), ASN.prefix.desc()).first():
			print("    __\__ {0}: {1}, {2}: {3}, {4}: {5}".format(colored("ASN", "cyan"), colored(row.id, "yellow"), colored("Prefix", "cyan"), colored(row.prefix, "yellow"), colored("Description", "cyan"), colored(row.description, "yellow")))
			print("   \\")

		else:
			print("      \__ {0}: {1}, {2}: {3}, {4}: {5}".format(colored("ASN", "cyan"), colored(row.id, "yellow"), colored("Prefix", "cyan"), colored(row.prefix, "yellow"), colored("Description", "cyan"), colored(row.description, "yellow")))

	print("    \__ {0}:".format(colored("New networks that were identified", "yellow")))

	for row in db.query(Network).filter(Network.domain == domain).order_by(Network.cidr):
		print("      \__ {0}: {1}, {2}: {3}, {4}: {5}".format(colored("CIDR", "cyan"), colored(row.cidr, "yellow"), colored("Identifier", "cyan"), colored(row.identifier, "yellow"), colored("Country", "cyan"), colored(row.country, "yellow")))
