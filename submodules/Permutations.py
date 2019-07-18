from termcolor import colored
from utilities.DatabaseHelpers import Resolution, Unresolved
from utilities.ScanHelpers import identifyWildcards, massResolve

def permuteDash(subdomain, wordlist):
	for word in wordlist:
		yield "-".join([word, subdomain])
		yield "-".join([subdomain, word])

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				yield subdomain.replace(part, "-".join([word, part]))
				yield subdomain.replace(part, "-".join([part, word]))


def permuteDot(subdomain, wordlist):
	for word in wordlist:
		yield ".".join([word, subdomain])
		yield ".".join([subdomain, word])

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				yield subdomain.replace(part, ".".join([word, part]))


def permuteWords(subdomain, wordlist):
	for word in wordlist:
		yield "".join([word, subdomain])
		yield "".join([subdomain, word])

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for word in wordlist:
				yield subdomain.replace(part, "".join([word, part]))
				yield subdomain.replace(part, "".join([part, word]))


def permuteNumbers(subdomain):
	for number in range(10):
		yield "-".join([subdomain, str(number)])
		yield "".join([subdomain, str(number)])

	if "." in subdomain:
		subParts = subdomain.split(".")

		for part in subParts:
			for number in range(10):
				yield subdomain.replace(part, "-".join([part, str(number)]))
				yield subdomain.replace(part, "".join([part, str(number)]))


def init(db, domain, wordlist, hideWildcards, threads):
	base = set()
	generators = []
	permutations = set()

	for row in db.query(Resolution).filter(Resolution.domain == domain, Resolution.isWildcard == False):
		if row.subdomain:
			base.add(row.subdomain)

	for row in db.query(Unresolved).filter(Unresolved.domain == domain):
		if row.subdomain:
			base.add(row.subdomain)

	print("{0} {1} {2}".format(colored("\n[*]-Performing permutations on", "yellow"), colored(len(base), "cyan"), colored("hostnames...", "yellow")))

	words = [line.strip() for line in wordlist.readlines()]
	wordlist.close()

	for subdomain in base:
		generators.append(permuteDash(subdomain, words))
		generators.append(permuteDot(subdomain, words))
		generators.append(permuteWords(subdomain, words))
		generators.append(permuteNumbers(subdomain))

	for generator in generators:
		for subdomain in generator:
			permutations.add((subdomain, "Permutations"))

	permutations = list(permutations)
	print("  \__ {0}: {1}".format(colored("Generated subdomains", "cyan"), colored(len(permutations), "yellow")))

	identifyWildcards(db, permutations, domain, threads)
	massResolve(db, permutations, domain, hideWildcards, threads)
