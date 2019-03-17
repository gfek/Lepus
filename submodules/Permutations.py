from time import time
from termcolor import colored
import utilities.MiscHelpers


def permuteDash(subdomain, wordlist):
	results = []

	for word in wordlist:
		results.append("-".join([word, subdomain]))
		results.append("-".join([subdomain, word]))

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				results.append(subdomain.replace(part, "-".join([word, part])))
				results.append(subdomain.replace(part, "-".join([part, word])))

	return results


def permuteDot(subdomain, wordlist):
	results = []

	for word in wordlist:
		results.append(".".join([word, subdomain]))
		results.append(".".join([subdomain, word]))

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				results.append(subdomain.replace(part, ".".join([word, part])))

	return results


def permuteWords(subdomain, wordlist):
	results = []

	for word in wordlist:
		results.append("".join([word, subdomain]))
		results.append("".join([subdomain, word]))

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				results.append(subdomain.replace(part, "".join([word, part])))
				results.append(subdomain.replace(part, "".join([part, word])))

	return results


def permuteNumbers(subdomain):
	results = []

	for number in range(10):
		results.append("-".join([subdomain, str(number)]))
		results.append("".join([subdomain, str(number)]))

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for number in range(10):
				results.append(subdomain.replace(part, "-".join([part, str(number)])))
				results.append(subdomain.replace(part, "".join([part, str(number)])))

	return results


def init(domain, resolved, collector_hosts, wildcards, wordlist):
	resolved_hosts = []

	for host in resolved:
		resolved_hosts.append(host)

	subdomains = utilities.MiscHelpers.uniqueList(resolved_hosts + collector_hosts)
	print("{0} {1} {2}".format(colored("\n[*]-Performing permutations on", "yellow"), colored(len(subdomains), "cyan"), colored("hostnames...", "yellow")))

	permutations = []
	words = [line.strip() for line in wordlist.readlines()]
	wordlist.close()

	for subdomain in subdomains:
		is_wildcard = False

		for hostnames in list(wildcards.values()):
			for hostname in hostnames:
				if hostname in subdomain:
					is_wildcard = True

		if is_wildcard:
			pass

		else:
			subdomain = subdomain.split(domain)[0][:-1]
			permutations += permuteDash(subdomain, words)
			permutations += permuteDot(subdomain, words)
			permutations += permuteWords(subdomain, words)
			permutations += permuteNumbers(subdomain)

	permutations = list(set(permutations))

	for i in range(len(permutations)):
		permutations[i] = ".".join([permutations[i], domain])

	for hostnames in list(wildcards.values()):
		for hostname in hostnames:
			permutations.append(".".join([str(int(time())), hostname]))

	print("  \__ {0}: {1}".format(colored("Generated subdomains", "cyan"), colored(len(permutations), "yellow")))
	return permutations
