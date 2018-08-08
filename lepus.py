from argparse import ArgumentParser
from warnings import simplefilter
from termcolor import colored
from time import sleep
import utils
import collectors.Censys
import collectors.CRT
import collectors.DNSDB
import collectors.DNSDumpster
import collectors.DNSTrails
import collectors.FindSubdomains
import collectors.GoogleTransparencyReport
import collectors.HackerTarget
import collectors.PassiveTotal
import collectors.Shodan
import collectors.ThreatCrowd
import collectors.VirusTotal
import collectors.WaybackMachine
import submodules.Permutations

simplefilter("ignore")


def printBanner():
	print colored("         ______  _____           ______  ", 'yellow')
	print colored(" |      |______ |_____) |     | (_____   ", 'yellow')
	print colored(" |_____ |______ |       |_____| ______)  ", 'yellow')
	print colored("                                   v2.0\n", 'cyan')
	sleep(1)


if __name__ == '__main__':
	printBanner()
	parser = ArgumentParser(prog="lepus.py", description='Infrastructure OSINT - find subdomains for a domain')
	parser.add_argument("domain", help="domain to search")
	parser.add_argument("-sw", "--show-wildcard", action="store_true", dest='showWildcard', help="show wildcard results [default is false]", default=False)
	parser.add_argument("-w", "--wordlist", action="store", dest='wordlist', help="wordlist with subdomains")
	parser.add_argument("-t", "--threads", action="store", dest='threads', help="number of threads [default is 100]", type=int, default=100)
	parser.add_argument("-j", "--json", action="store_true", dest='json', help="output to json as well [default is '|' delimited csv]", default=False)
	parser.add_argument("-nc", "--no-collectors", action="store_true", dest='noCollectors', help="don't use collectors [default is false]", default=False)
	parser.add_argument("--permutate", action="store_true", dest='permutate', help="perform permutations on resolved domains", default=False)
	parser.add_argument("-pw", "--permutation-wordlist", dest='permutation_wordlist', help="wordlist to perform permutations with [default is ./lists/words.txt]", type=str, default="lists/words.txt")
	parser.add_argument("-v", "--version", action="version", version="%(prog)s v2.0")
	args = parser.parse_args()

	if args.domain is None:
		parser.parse_args(['-h'])

	try:
		workspace = utils.createWorkspace(args.domain)
		wildcard = utils.checkWildcard(args.domain, args.showWildcard)
		utils.getDNSrecords(args.domain, args.json)

		if not workspace:
			old_findings = utils.loadOldFindings(args.domain)

		else:
			old_findings = []

		if args.noCollectors:
			collector_hosts = []
		else:
			print
			collector_hosts = []
			collector_hosts += collectors.Censys.init(args.domain)
			collector_hosts += collectors.CRT.init(args.domain)
			collector_hosts += collectors.DNSDB.init(args.domain)
			collector_hosts += collectors.DNSDumpster.init(args.domain)
			collector_hosts += collectors.DNSTrails.init(args.domain)
			collector_hosts += collectors.FindSubdomains.init(args.domain)
			collector_hosts += collectors.GoogleTransparencyReport.init(args.domain)
			collector_hosts += collectors.HackerTarget.init(args.domain)
			collector_hosts += collectors.PassiveTotal.init(args.domain)
			collector_hosts += collectors.Shodan.init(args.domain)
			collector_hosts += collectors.ThreatCrowd.init(args.domain)
			collector_hosts += collectors.VirusTotal.init(args.domain)
			collector_hosts += collectors.WaybackMachine.init(args.domain)

		if args.wordlist:
			wordlist_hosts = utils.loadWordlist(args.domain, args.wordlist)

		else:
			wordlist_hosts = []

		hosts = old_findings + collector_hosts + wordlist_hosts

		if len(hosts) > 0:
			resolved = utils.massResolve(args.domain, set(utils.filterDomain(args.domain, hosts)), set(utils.filterDomain(args.domain, collector_hosts)), args.threads, wildcard, args.json, [])

			if args.permutate:
				permutated_hosts = submodules.Permutations.init(args.domain, resolved, args.permutation_wordlist)

				if permutated_hosts is not None:
					hosts += permutated_hosts
					resolved = utils.massResolve(args.domain, set(utils.filterDomain(args.domain, hosts)), set(utils.filterDomain(args.domain, collector_hosts)), args.threads, wildcard, args.json, resolved)

			else:
				pass

			IPs = set([address for hostname, address in resolved.items()])
			utils.massASN(args.domain, IPs, args.threads, args.json)
			utils.massWHOIS(args.domain, IPs, args.threads, args.json)
			utils.deleteEmptyFiles(args.domain)

	except KeyboardInterrupt:
		print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
		sleep(2)
		exit(-1)
