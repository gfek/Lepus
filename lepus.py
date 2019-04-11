#!/usr/bin/env python3

from argparse import ArgumentParser, FileType
from warnings import simplefilter
from termcolor import colored
from time import sleep, time
from os.path import join
from gc import collect
import collectors.Censys
import collectors.CertSpotter
import collectors.CRT
# import collectors.DNSDB
import collectors.DNSTrails
import collectors.EntrustCertificates
import collectors.FindSubdomains
import collectors.GoogleTransparency
import collectors.HackerTarget
import collectors.PassiveTotal
import collectors.ProjectSonar
import collectors.Riddler
import collectors.Shodan
import collectors.ThreatCrowd
import collectors.VirusTotal
import collectors.WaybackMachine
"""
import submodules.Permutations
import submodules.PortScan
import submodules.ReverseLookups
import submodules.TakeOver
"""
import utilities.DatabaseHelpers
import utilities.MiscHelpers
import utilities.ScanHelpers

simplefilter("ignore")
version = "3.2.0"


def printBanner():
	print(colored("         ______  _____           ______", "yellow"))
	print(colored(" |      |______ |_____) |     | (_____ ", "yellow"))
	print(colored(" |_____ |______ |       |_____| ______)", "yellow"))
	print(colored("                                v{0}".format(version), "cyan"))
	sleep(1)


if __name__ == "__main__":
	parser = ArgumentParser(prog="lepus.py", description="Infrastructure OSINT")
	parser.add_argument("domain", help="domain to search")
	parser.add_argument("-w", "--wordlist", action="store", dest="wordlist", help="wordlist with subdomains", type=FileType("r"))
	parser.add_argument("-t", "--threads", action="store", dest="threads", help="number of threads [default is 100]", type=int, default=100)
	parser.add_argument("-j", "--json", action="store_true", dest="json", help="output to json as well [default is '|' delimited csv]", default=False)
	parser.add_argument("-nc", "--no-collectors", action="store_true", dest="noCollectors", help="skip passive subdomain enumeration", default=False)
	parser.add_argument("-zt", "--zone-transfer", action="store_true", dest="zoneTransfer", help="attempt to zone transfer from identified name servers", default=False)
	parser.add_argument("--permutate", action="store_true", dest="permutate", help="perform permutations on resolved domains", default=False)
	parser.add_argument("-pw", "--permutation-wordlist", dest="permutation_wordlist", help="wordlist to perform permutations with [default is lists/words.txt]", type=FileType("r"), default="lists/words.txt")
	parser.add_argument("--reverse", action="store_true", dest="reverse", help="perform reverse dns lookups on resolved public IP addresses", default=False)
	parser.add_argument("-r", "--ranges", action="store", dest="ranges", help="comma seperated ip ranges to perform reverse dns lookups on", type=str, default=None)
	parser.add_argument("--portscan", action="store_true", dest="portscan", help="scan resolved public IP addresses for open ports", default=False)
	parser.add_argument("-p", "--ports", action="store", dest="ports", help="set of ports to be used by the portscan module [default is medium]", type=str)
	parser.add_argument("--takeover", action="store_true", dest="takeover", help="check identified hosts for potential subdomain take-overs", default=False)
	parser.add_argument("-v", "--version", action="version", version="Lepus v{0}".format(version))
	args = parser.parse_args()

	if not utilities.MiscHelpers.checkArgumentValidity(parser, args):
		exit(1)

	printBanner()

	try:
		db = utilities.DatabaseHelpers.init()
		workspace = utilities.MiscHelpers.createWorkspace(args.domain)
		nameservers = utilities.ScanHelpers.getDNSrecords(args.domain, args.json)

		if not workspace:
			# old_findings, old_resolved_public, last_run, collector_hosts = utilities.MiscHelpers.loadOldFindings(args.domain)
			current_run = str(int(time()))

			with open(join("results", args.domain, ".timestamp"), "w") as timestamp_file:
				timestamp_file.write(current_run)

		else:
			collector_hosts = []
			old_findings = []
			old_resolved_public = []
			last_run = None
			current_run = str(int(time()))

			with open(join("results", args.domain, ".timestamp"), "w") as timestamp_file:
				timestamp_file.write(current_run)

		# ------------------------------------------------ #

		if args.zoneTransfer:
			zt_subdomains = utilities.ScanHelpers.zoneTransfer(args.domain, nameservers)

		else:
			zt_subdomains = None

		# ------------------------------------------------ #

		if args.noCollectors:
			pass

		else:
			print()
			collector_subdomains = []
			collector_subdomains += collectors.Censys.init(args.domain)
			collector_subdomains += collectors.CertSpotter.init(args.domain)
			collector_subdomains += collectors.CRT.init(args.domain)
			collector_subdomains += collectors.DNSDB.init(args.domain)
			collector_subdomains += collectors.DNSTrails.init(args.domain)
			collector_subdomains += collectors.EntrustCertificates.init(args.domain)
			collector_subdomains += collectors.FindSubdomains.init(args.domain)
			collector_subdomains += collectors.GoogleTransparency.init(args.domain)
			collector_subdomains += collectors.HackerTarget.init(args.domain)
			collector_subdomains += collectors.PassiveTotal.init(args.domain)
			collector_subdomains += collectors.ProjectSonar.init(args.domain)
			collector_subdomains += collectors.Riddler.init(args.domain)
			collector_subdomains += collectors.Shodan.init(args.domain)
			collector_subdomains += collectors.ThreatCrowd.init(args.domain)
			collector_subdomains += collectors.VirusTotal.init(args.domain)
			collector_subdomains += collectors.WaybackMachine.init(args.domain)
			collector_subdomains = utilities.MiscHelpers.filterDomain(args.domain, utilities.MiscHelpers.uniqueList(collector_subdomains))

		# ------------------------------------------------ #

		if args.wordlist:
			wordlist_subdomains = utilities.MiscHelpers.loadWordlist(args.domain, args.wordlist)

		else:
			wordlist_subdomains = None

		# ------------------------------------------------ #

		# TO-DO - redesign old findings
		findings = utilities.MiscHelpers.combineFindings(zt_subdomains, collector_subdomains, wordlist_subdomains)

		del zt_subdomains
		del collector_subdomains
		del wordlist_subdomains
		collect()

		if len(findings) > 0:
			utilities.ScanHelpers.identifyWildcards(db, findings, args.domain, args.threads)
			utilities.ScanHelpers.massResolve(db, findings, args.domain, args.threads)

			del findings
			collect()

			# hosts = list(set(old_findings + zone_hosts + collector_hosts + [hostname for hostname, address in list(resolved.items())]))

			"""
			if args.permutate:
				permutated_hosts = submodules.Permutations.init(args.domain, resolved, collector_hosts, wildcards, args.permutation_wordlist)
				permutated_hosts = utilities.MiscHelpers.filterDomain(args.domain, utilities.MiscHelpers.uniqueList(permutated_hosts))

				if permutated_hosts is not None:
					hosts = utilities.MiscHelpers.uniqueList(hosts + permutated_hosts)
					wildcards = utilities.ScanHelpers.identifyWildcards(args.domain, wildcards, hosts, args.threads, args.json)
					resolved, resolved_public = utilities.ScanHelpers.massResolve(args.domain, hosts, collector_hosts, args.threads, wildcards, args.json, resolved)

			public_IPs = set([address for hostname, address in list(resolved_public.items())])

			if args.reverse:
				resolved_public = submodules.ReverseLookups.init(args.domain, args.ranges, resolved_public, public_IPs, args.threads, args.json)
				public_IPs = set([address for hostname, address in list(resolved_public.items())])

			if resolved_public and old_resolved_public:
				utilities.MiscHelpers.diffLastRun(args.domain, wildcards, resolved_public, old_resolved_public, last_run, current_run)

			utilities.ScanHelpers.massRDAP(args.domain, public_IPs, args.threads, args.json)

			if args.portscan:
				submodules.PortScan.init(args.domain, resolved_public, public_IPs, args.ports, args.threads)

			if args.takeover:
				if old_resolved_public:
					collector_hosts = collector_hosts + old_resolved_public

				submodules.TakeOver.init(args.domain, resolved_public, collector_hosts, args.threads, args.json)

			utilities.MiscHelpers.deleteEmptyFiles(args.domain)
			"""

		print()

	except KeyboardInterrupt:
		print(colored("\n[*]-Received keyboard interrupt! Shutting down...\n", "red"))
		exit(-1)
