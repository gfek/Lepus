#!/usr/bin/python

from argparse import ArgumentParser
from warnings import simplefilter
from termcolor import colored
from time import sleep, time
from os.path import join
import utils
import collectors.Censys
import collectors.CertSpotter
import collectors.CRT
import collectors.DNSDB
import collectors.DNSDumpster
import collectors.DNSTrails
import collectors.EntrustCertificates
import collectors.FindSubdomains
import collectors.GoogleTransparency
import collectors.HackerTarget
import collectors.PassiveTotal
import collectors.Riddler
import collectors.Shodan
import collectors.ThreatCrowd
import collectors.VirusTotal
import collectors.WaybackMachine
import submodules.Permutations
import submodules.PortScan
import submodules.ReverseLookups

simplefilter("ignore")


def printBanner():
	print colored("         ______  _____           ______  ", 'yellow')
	print colored(" |      |______ |_____) |     | (_____   ", 'yellow')
	print colored(" |_____ |______ |       |_____| ______)  ", 'yellow')
	print colored("                                v2.2.5", 'cyan')
	sleep(1)


if __name__ == '__main__':
	parser = ArgumentParser(prog="lepus.py", description='Infrastructure OSINT - find subdomains for a domain')
	parser.add_argument("domain", help="domain to search")
	parser.add_argument("-w", "--wordlist", action="store", dest='wordlist', help="wordlist with subdomains")
	parser.add_argument("-t", "--threads", action="store", dest='threads', help="number of threads [default is 100]", type=int, default=100)
	parser.add_argument("-j", "--json", action="store_true", dest='json', help="output to json as well [default is '|' delimited csv]", default=False)
	parser.add_argument("-nc", "--no-collectors", action="store_true", dest='noCollectors', help="don't use collectors [default is false]", default=False)
	parser.add_argument("--permutate", action="store_true", dest='permutate', help="perform permutations on resolved domains", default=False)
	parser.add_argument("-pw", "--permutation-wordlist", dest='permutation_wordlist', help="wordlist to perform permutations with [default is lists/words.txt]", type=str, default="lists/words.txt")
	parser.add_argument("--reverse", action="store_true", dest='reverse', help="perform reverse dns lookups on resolved public IP addresses", default=False)
	parser.add_argument("--portscan", action="store_true", dest='port_scan', help="scan resolved public IP addresses for open ports", default=False)
	parser.add_argument("-p", "--ports", action="store", dest='ports', help="set of ports to be used by the portscan module [default is medium]", default="medium")
	parser.add_argument("-v", "--version", action="version", version="%(prog)s v2.2.5")
	args = parser.parse_args()

	printBanner()

	try:
		workspace = utils.createWorkspace(args.domain)
		utils.getDNSrecords(args.domain, args.json)

		if not workspace:
			old_findings, old_resolved_public, last_run, collector_hosts = utils.loadOldFindings(args.domain)

		else:
			collector_hosts = []
			old_findings = []
			old_resolved_public = []
			last_run = None

			with open(join("results", args.domain, ".timestamp"), 'w') as timestamp_file:
				timestamp_file.write(str(int(time())))

		if args.noCollectors:
			pass

		else:
			print
			collector_hosts = []
			collector_hosts += collectors.Censys.init(args.domain)
			collector_hosts += collectors.CertSpotter.init(args.domain)
			collector_hosts += collectors.CRT.init(args.domain)
			collector_hosts += collectors.DNSDB.init(args.domain)
			collector_hosts += collectors.DNSDumpster.init(args.domain)
			collector_hosts += collectors.DNSTrails.init(args.domain)
			collector_hosts += collectors.EntrustCertificates.init(args.domain)
			collector_hosts += collectors.FindSubdomains.init(args.domain)
			collector_hosts += collectors.GoogleTransparency.init(args.domain)
			collector_hosts += collectors.HackerTarget.init(args.domain)
			collector_hosts += collectors.PassiveTotal.init(args.domain)
			collector_hosts += collectors.Riddler.init(args.domain)
			collector_hosts += collectors.Shodan.init(args.domain)
			collector_hosts += collectors.ThreatCrowd.init(args.domain)
			collector_hosts += collectors.VirusTotal.init(args.domain)
			collector_hosts += collectors.WaybackMachine.init(args.domain)
			collector_hosts = utils.filterDomain(args.domain, utils.uniqueList(collector_hosts))
			utils.saveCollectorResults(args.domain, collector_hosts)

		if args.wordlist:
			wordlist_hosts = utils.loadWordlist(args.domain, args.wordlist)

		else:
			wordlist_hosts = []

		hosts = utils.filterDomain(args.domain, utils.uniqueList(old_findings + collector_hosts + wordlist_hosts))
		wildcards = utils.identifyWildcards(args.domain, hosts, args.threads, {}, args.json)

		if len(hosts) > 0:
			resolved, resolved_public = utils.massResolve(args.domain, hosts, collector_hosts, args.threads, wildcards, args.json, [])
			hosts = list(set(old_findings + collector_hosts + [hostname for hostname, address in resolved.items()]))

			if args.permutate:
				permutated_hosts = submodules.Permutations.init(args.domain, resolved, wildcards, args.permutation_wordlist)
				permutated_hosts = utils.filterDomain(args.domain, utils.uniqueList(permutated_hosts))

				if permutated_hosts is not None:
					hosts = utils.uniqueList(hosts + permutated_hosts)
					wildcards = utils.identifyWildcards(args.domain, hosts, args.threads, wildcards, args.json)
					resolved, resolved_public = utils.massResolve(args.domain, hosts, collector_hosts, args.threads, wildcards, args.json, resolved)

			public_IPs = set([address for hostname, address in resolved_public.items()])

			if args.reverse:
				resolved_public = submodules.ReverseLookups.init(args.domain, resolved_public, public_IPs, args.threads, args.json)

			if len(public_IPs) > 0:
				if args.port_scan:
					submodules.PortScan.init(resolved_public, args.domain, public_IPs, args.ports, args.threads)

				utils.massASN(args.domain, public_IPs, args.threads, args.json)
				utils.massWHOIS(args.domain, public_IPs, args.threads, args.json)

			utils.diffLastRun(args.domain, resolved_public, old_resolved_public, last_run, args.json)
			utils.deleteEmptyFiles(args.domain)

			print

	except KeyboardInterrupt:
		print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
		sleep(2)
		exit(-1)
