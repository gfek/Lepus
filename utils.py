from IPy import IP
from tqdm import tqdm
from json import dumps
from ipwhois import IPWhois
from ipwhois.net import Net
from termcolor import colored
from ipwhois.asn import IPASN
from dns.name import EmptyLabel
from socket import gethostbyname
from time import sleep, time, ctime
from dns.exception import DNSException
from os.path import exists, isfile, join
from os import makedirs, listdir, stat, remove
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns.resolver import Resolver, NXDOMAIN, NoAnswer, NoNameservers, Timeout
import concurrent.futures.thread


def deleteEmptyFiles(directory):
	try:
		filenames = [filename for filename in listdir(join("results", directory)) if isfile(join("results", directory, filename))]

		for filename in filenames:
			if stat(join("results", directory, filename)).st_size == 0:
				remove(join("results", directory, filename))

	except OSError:
		pass


def diffLastRun(domain, resolved_public, old_resolved_public, last_run, out_to_json):
	if old_resolved_public:
		print "{0} - {1}".format(colored("\n[*]-Differences from last run", 'yellow'), colored(ctime(int(last_run)), 'cyan'))
		diff = {}

		for host, ip in resolved_public.items():
			if host not in old_resolved_public:
				print "  \__", colored("[+]", 'green'), colored("{0} ({1})".format(host, ip), 'white')
				diff[host] = ip

		if out_to_json:
			try:
				with open(join("results", domain, "diff.json"), "w") as diff_file:
					diff_file.write("{0}\n".format(dumps(diff)))

			except OSError:
				pass

			except IOError:
				pass

		try:
			with open(join("results", domain, "diff.csv"), "w") as diff_file:
				for host, ip in diff.items():
					diff_file.write("{0}|{1}\n".format(host, ip))

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
			with open(join("results", domain, "collector_results.txt"), "w") as collector_file:
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

	print colored("\n[*]-Loading Old Findings...", 'yellow')

	for filename in filenames:
		if "resolved" in filename:
			try:
				with open(join("results", directory, filename), 'r') as old_file:
					lines = old_file.readlines()

					for line in lines:
						OF.append(line.split('|')[0])

						if "public" in filename:
							ORP.append(line.split('|')[0])

			except OSError:
				pass

			except IOError:
				pass

		if filename == ".timestamp":
			with open(join("results", directory, filename), 'r') as timestamp_file:
				last_run = timestamp_file.read()

		if filename == "collector_results.txt":
			with open(join("results", directory, filename), 'r') as collector_file:
				collector_results += [line.strip() for line in collector_file.readlines()]

	print "  \__", colored("Unique subdomains loaded:", 'cyan'), colored(len(OF), 'yellow')
	return OF, ORP, last_run, collector_results


def loadWordlist(domain, filepath):
	print colored("\n[*]-Loading Wordlist...", 'yellow')

	with open(filepath, 'r') as wordlist:
		WL = set(['.'.join([subdomain.strip().lower(), domain]) for subdomain in wordlist.readlines()])

	print "  \__", colored("Unique subdomains loaded:", 'cyan'), colored(len(WL), 'yellow')
	return list(WL)


def getDNSrecords(domain, out_to_json):
	print colored("\n[*]-Retrieving DNS Records...", 'yellow')

	RES = {}
	MX = []
	NS = []
	A = []
	AAAA = []
	SOA = []
	TXT = []

	resolver = Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1

	rrtypes = ['A', 'MX', 'NS', 'AAAA', 'SOA', 'TXT']

	for r in rrtypes:
		try:
			Aanswer = resolver.query(domain, r)

			for answer in Aanswer:
				if r == 'A':
					A.append(answer.address)
					RES.update({r: A})

				if r == 'MX':
					MX.append(answer.exchange.to_text()[:-1])
					RES.update({r: MX})

				if r == 'NS':
					NS.append(answer.target.to_text()[:-1])
					RES.update({r: NS})

				if r == 'AAAA':
					AAAA.append(answer.address)
					RES.update({r: AAAA})

				if r == 'SOA':
					SOA.append(answer.mname.to_text()[:-1])
					RES.update({r: SOA})

				if r == 'TXT':
					TXT.append(str(answer))
					RES.update({r: TXT})

		except NXDOMAIN:
			pass

		except NoAnswer:
			pass

		except EmptyLabel:
			pass

		except NoNameservers:
			pass

		except Timeout:
			pass

		except DNSException:
			pass

	for key, value in RES.iteritems():
		for record in value:
			print "  \__", colored(key, 'cyan'), ":", colored(record, 'yellow')

	if out_to_json:
		try:
			with open(join("results", domain, "dns.json"), "w") as dns_file:
				dns_file.write(dumps(RES))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "dns.csv"), "w") as dns_file:
			for key, value in RES.iteritems():
				for record in value:
					dns_file.write("{0}|{1}\n".format(key, record))

	except OSError:
		pass

	except IOError:
		pass


def checkWildcard(domain):
	resolution = resolve('.'.join([str(int(time())), domain]))

	if None in resolution:
		return None

	else:
		return (domain, resolution[1])


def identifyWildcards(domain, hosts, threads, previously_identified, out_to_json):
	sub_levels = uniqueSubdomainLevels(hosts)
	wildcards = []

	if len(sub_levels) <= 100000:
		print colored("\n[*]-Checking for wildcards...", 'yellow')
	else:
		print colored("\n[*]-Checking for wildcards, in chunks of 100,000...", 'yellow')

	subLevelChunks = list(chunks(list(sub_levels), 100000))
	iteration = 1

	for subLevelChunk in subLevelChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(checkWildcard, sub_level) for sub_level in subLevelChunk}

			try:
				completed = as_completed(tasks)
				completed = tqdm(completed, total=len(subLevelChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, len(subLevelChunks)), 'cyan')), dynamic_ncols=True)

				for task in completed:
					result = task.result()

					if result is not None:
						wildcards.append(result)

			except KeyboardInterrupt:
				executor._threads.clear()
				concurrent.futures.thread._threads_queues.clear()
				print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
				sleep(2)
				exit(-1)

		iteration += 1

	optimized_wildcards = {}

	if wildcards:
		reversed_wildcards = [('.'.join(reversed(hostname.split('.'))), ip) for hostname, ip in wildcards]
		sorted_wildcards = sorted(reversed_wildcards, key=lambda rw: rw[0])

		for reversed_hostname, ip in sorted_wildcards:
			hostname = '.'.join(reversed(reversed_hostname.split('.')))
			new_wildcard = True

			if ip in optimized_wildcards:
				for entry in optimized_wildcards[ip]:
					if len(hostname.split('.')) > len(entry.split('.')):
						if entry in hostname:
							new_wildcard = False

				if new_wildcard:
					optimized_wildcards[ip].append(hostname)

			else:
				optimized_wildcards[ip] = [hostname]

		print "    \__ {0} {1}".format(colored("Wildcards that were identified:", "yellow"), colored(sum(len(hostnames) for hostnames in optimized_wildcards.values()) - sum(len(hostnames) for hostnames in previously_identified.values()), "cyan"))

		for ip, hostnames in optimized_wildcards.items():
			for hostname in hostnames:
				if previously_identified:
					if ip in previously_identified:
						if hostname in previously_identified[ip]:
							pass

						else:
							print "      \__ {0}.{1} ==> {2}".format(colored('*', "red"), colored(hostname, "cyan"), colored(ip, 'red'))

					else:
						print "      \__ {0}.{1} ==> {2}".format(colored('*', "red"), colored(hostname, "cyan"), colored(ip, 'red'))

				else:
					print "      \__ {0}.{1} ==> {2}".format(colored('*', "red"), colored(hostname, "cyan"), colored(ip, 'red'))

		if out_to_json:
			try:
				with open(join("results", domain, "wildcards.json"), "w") as wildcard_file:
					wildcard_file.write("{0}\n".format(dumps(optimized_wildcards)))

			except OSError:
				pass

			except IOError:
				pass

		try:
			with open(join("results", domain, "wildcards.csv"), "w") as wildcard_file:
				for ip, hostnames in optimized_wildcards.items():
					for hostname in hostnames:
						wildcard_file.write("{0}|{1}\n".format(hostname, ip))

		except OSError:
			pass

		except IOError:
			pass

	return optimized_wildcards


def uniqueSubdomainLevels(hosts):
	unique_subs = set()

	for host in hosts:
		unique_subs.add('.'.join(sub for sub in host.split('.')[1:]))

	return list(unique_subs)


def uniqueList(subdomains):
	uniqe_subdomains = set()

	for subdomain in subdomains:
		uniqe_subdomains.add(subdomain.lower())

	return list(uniqe_subdomains)


def filterDomain(domain, subdomains):
	domain_parts = domain.split('.')
	filtered = []

	for subdomain in subdomains:
		subdomain_parts = subdomain.split('.')

		if domain_parts == subdomain_parts[-1 * len(domain_parts):]:
			filtered.append(subdomain)

	return filtered


def resolve(hostname):
	try:
		return (hostname, gethostbyname(hostname))

	except Exception:
		return (hostname, None)


def chunks(list, numberInChunk):
	for i in range(0, len(list), numberInChunk):
		yield list[i:i + numberInChunk]


def massResolve(domain, hostnames, collector_hostnames, threads, wildcards, out_to_json, already_resolved):
	resolved = {}
	resolved_public = {}
	resolved_private = {}
	resolved_reserved = {}
	resolved_loopback = {}
	resolved_carrier_grade_nat = {}
	unresolved = {}

	if len(hostnames) <= 100000:
		print "{0} {1} {2}".format(colored("\n[*]-Attempting to resolve", "yellow"), colored(len(hostnames), "cyan"), colored("hostnames...", "yellow"))
	else:
		print "{0} {1} {2}".format(colored("\n[*]-Attempting to resolve", "yellow"), colored(len(hostnames), "cyan"), colored("hostnames, in chunks of 100,000...", "yellow"))

	hostNameChunks = list(chunks(list(hostnames), 100000))
	iteration = 1

	for hostNameChunk in hostNameChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(resolve, hostname) for hostname in hostNameChunk}

			try:
				completed = as_completed(tasks)
				completed = tqdm(completed, total=len(hostNameChunk), desc="  \__ {0}".format(colored("Progress {0}/{1}".format(iteration, len(hostNameChunks)), 'cyan')), dynamic_ncols=True)

				for task in completed:
					try:
						result = task.result()

						if None not in result and result[1] not in wildcards:
							ip_type = IP(result[1]).iptype()

							if ip_type == "PUBLIC":
								resolved[result[0]] = result[1]
								resolved_public[result[0]] = result[1]

							elif ip_type == "PRIVATE":
								resolved[result[0]] = result[1]
								resolved_private[result[0]] = result[1]

							elif ip_type == "RESERVED":
								resolved[result[0]] = result[1]
								resolved_reserved[result[0]] = result[1]

							elif ip_type == "LOOPBACK":
								resolved[result[0]] = result[1]
								resolved_loopback[result[0]] = result[1]

							elif ip_type == "CARRIER_GRADE_NAT":
								resolved[result[0]] = result[1]
								resolved_carrier_grade_nat[result[0]] = result[1]

						elif None not in result and result[1] in wildcards:
							actual_wildcard = False

							for value in wildcards[result[1]]:
								if value in result[0]:
									actual_wildcard = True

							if not actual_wildcard or result[0] in collector_hostnames:
								ip_type = IP(result[1]).iptype()

								if ip_type == "PUBLIC":
									resolved[result[0]] = result[1]
									resolved_public[result[0]] = result[1]

								elif ip_type == "PRIVATE":
									resolved[result[0]] = result[1]
									resolved_private[result[0]] = result[1]

								elif ip_type == "RESERVED":
									resolved[result[0]] = result[1]
									resolved_reserved[result[0]] = result[1]

								elif ip_type == "LOOPBACK":
									resolved[result[0]] = result[1]
									resolved_loopback[result[0]] = result[1]

								elif ip_type == "CARRIER_GRADE_NAT":
									resolved[result[0]] = result[1]
									resolved_carrier_grade_nat[result[0]] = result[1]

						elif None in result:
							if result[0] in collector_hostnames:
								unresolved[result[0]] = result[1]

					except Exception:
						continue

			except KeyboardInterrupt:
				executor._threads.clear()
				concurrent.futures.thread._threads_queues.clear()
				print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
				sleep(2)
				exit(-1)

		iteration += 1

	print "    \__ {0} {1}".format(colored("Hostnames that were resolved:", "yellow"), colored(len(resolved) - len(already_resolved), "cyan"))

	for hostname, address in resolved.items():
		if hostname not in already_resolved:
			if address in wildcards:
				actual_wildcard = False

				for value in wildcards[address]:
					if value in hostname:
						actual_wildcard = True

				if actual_wildcard:
					print "      \__ {0} {1}".format(colored(hostname, "cyan"), colored(address, 'red'))

				else:
					print "      \__ {0} {1}".format(colored(hostname, "cyan"), colored(address, 'yellow'))

			else:
				print "      \__ {0} {1}".format(colored(hostname, "cyan"), colored(address, 'yellow'))

	if out_to_json:
		try:
			with open(join("results", domain, "resolved_public.json"), "w") as resolved_public_file:
				if resolved_public:
					resolved_public_file.write("{0}\n".format(dumps(resolved_public)))

		except OSError:
			pass

		except IOError:
			pass

		try:
			with open(join("results", domain, "resolved_private.json"), "w") as resolved_private_file:
				if resolved_private:
					resolved_private_file.write("{0}\n".format(dumps(resolved_private)))

		except OSError:
			pass

		except IOError:
			pass

		try:
			with open(join("results", domain, "resolved_reserved.json"), "w") as resolved_reserved_file:
				if resolved_reserved:
					resolved_reserved_file.write("{0}\n".format(dumps(resolved_reserved)))

		except OSError:
			pass

		except IOError:
			pass

		try:
			with open(join("results", domain, "resolved_loopback.json"), "w") as resolved_loopback_file:
				if resolved_loopback:
					resolved_loopback_file.write("{0}\n".format(dumps(resolved_loopback)))

		except OSError:
			pass

		except IOError:
			pass

		try:
			with open(join("results", domain, "resolved_carrier_grade_nat.json"), "w") as resolved_carrier_grade_nat_file:
				if resolved_carrier_grade_nat:
					resolved_carrier_grade_nat_file.write("{0}\n".format(dumps(resolved_carrier_grade_nat)))

		except OSError:
			pass

		except IOError:
			pass

		try:
			with open(join("results", domain, "unresolved.json"), "w") as unresolved_file:
				if unresolved:
					unresolved_file.write("{0}\n".format(dumps(unresolved)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "resolved_public.csv"), "w") as resolved_public_file:
			for hostname, address in resolved_public.items():
				resolved_public_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	try:
		with open(join("results", domain, "resolved_private.csv"), "w") as resolved_private_file:
			for hostname, address in resolved_private.items():
				resolved_private_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	try:
		with open(join("results", domain, "resolved_reserved.csv"), "w") as resolved_reserved_file:
			for hostname, address in resolved_reserved.items():
				resolved_reserved_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	try:
		with open(join("results", domain, "resolved_loopback.csv"), "w") as resolved_loopback_file:
			for hostname, address in resolved_loopback.items():
				resolved_loopback_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	try:
		with open(join("results", domain, "resolved_carrier_grade_nat.csv"), "w") as resolved_carrier_grade_nat_file:
			for hostname, address in resolved_carrier_grade_nat.items():
				resolved_carrier_grade_nat_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	try:
		with open(join("results", domain, "unresolved.csv"), "w") as unresolved_file:
			for hostname, address in unresolved.items():
				unresolved_file.write("{0}|{1}\n".format(hostname, address))

	except OSError:
		pass

	except IOError:
		pass

	return resolved, resolved_public


def asn(ip):
	net = Net(ip)
	obj = IPASN(net)
	results = obj.lookup()

	return results


def massASN(domain, IPs, threads, out_to_json):
	print "{0} {1} {2}".format(colored("\n[*]-Retrieving unique Autonomous Systems for", "yellow"), colored(len(IPs), "cyan"), colored("unique public IPs...", "yellow"))

	ip2asn = {}

	try:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(asn, ip): ip for ip in IPs}
			try:
				completed = as_completed(tasks)
				completed = tqdm(completed, total=len(IPs), desc="  \__ {0}".format(colored("Progress", 'cyan')), dynamic_ncols=True)

				for task in completed:
					try:
						ip2asn.update({tasks[task]: task.result()})

					except Exception:
						pass

			except KeyboardInterrupt:
				executor._threads.clear()
				concurrent.futures.thread._threads_queues.clear()
				print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
				sleep(2)
				exit(-1)

	except ValueError:
		pass

	ip2asn_values = []

	for key, value in ip2asn.items():
		if value not in ip2asn_values and value['asn_cidr'] != "NA" and value['asn_cidr'] is not None and value['asn'] != "NA" and value['asn'] is not None and value['asn_description'] != "NA" and value['asn_description'] is not None:
			ip2asn_values.append(value)

	print "    \__ {0} {1}".format(colored("ASNs that were identified:", "yellow"), colored(len(ip2asn_values), "cyan"))

	for value in ip2asn_values:
		print "      \__", colored("ASN", 'cyan'), ':', colored(value['asn'], 'yellow'), colored("BGP Prefix", 'cyan'), ':', colored(value['asn_cidr'], 'yellow'), colored("AS Name", 'cyan'), ':', colored(value['asn_description'], 'yellow')

	if out_to_json:
		ip2asn_json = {}

		for value in ip2asn_values:
			ip2asn_json[value['asn']] = [value['asn_cidr'], value['asn_description']]

		try:
			with open(join("results", domain, "asn.json"), "w") as asn_file:
				asn_file.write("{0}\n".format(dumps(ip2asn_json)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "asn.csv"), "w") as asn_file:
			for value in ip2asn_values:
				asn_file.write("{0}|{1}|{2}\n".format(value['asn_cidr'], value['asn'], value['asn_description']))

	except OSError:
		pass

	except IOError:
		pass


def whois(ip):
	obj = IPWhois(ip)
	results = obj.lookup_whois()

	return results['nets']


def massWHOIS(domain, IPs, threads, out_to_json):
	print "{0} {1} {2}".format(colored("\n[*]-Retrieving unique WHOIS records for", "yellow"), colored(len(IPs), "cyan"), colored("unique public IPs...", "yellow"))

	ip2whois = {}

	try:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(whois, ip): ip for ip in IPs}

			try:
				completed = as_completed(tasks)
				completed = tqdm(completed, total=len(IPs), desc="  \__ {0}".format(colored("Progress", 'cyan')), dynamic_ncols=True)

				for task in completed:
					try:
						if task.result()[0]['name'] is not None:
							ip2whois[task.result()[0]['range']] = task.result()[0]['name']

					except Exception:
						pass

			except KeyboardInterrupt:
				executor._threads.clear()
				concurrent.futures.thread._threads_queues.clear()
				print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
				sleep(2)
				exit(-1)

	except ValueError:
		pass

	print "    \__ {0} {1}".format(colored("WHOIS records that were identified:", "yellow"), colored(len(ip2whois), "cyan"))

	for ip_range, name in ip2whois.items():
		print "      \__", colored(ip_range, 'cyan'), ':', colored(name, 'yellow')

	if out_to_json:
		try:
			with open(join("results", domain, "whois.json"), "w") as whois_file:
				whois_file.write("{0}\n".format(dumps(ip2whois)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "whois.csv"), "w") as whois_file:
			for ip_range, name in ip2whois.items():
				whois_file.write("{0}|{1}\n".format(ip_range, name))

	except OSError:
		pass

	except IOError:
		pass
