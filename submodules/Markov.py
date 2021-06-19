import copy
import random
import argparse
from tqdm import tqdm
from gc import collect
from termcolor import colored
from collections import defaultdict
from utilities.DatabaseHelpers import Resolution, Unresolved
from concurrent.futures import ThreadPoolExecutor, as_completed
from utilities.ScanHelpers import identifyWildcards, massResolve
import utilities.MiscHelpers


class MarkovChain:

	def __init__(self, n=8):
		self.transition_dict = defaultdict(lambda: [])
		self.state = ""
		self.state_size = n


	def update(self, data):
		tupled_data = self.tupleify(data)
		
		for c in range(len(tupled_data)):
			self.transition_dict[tupled_data[c][0]].append(tupled_data[c][1])


	def tupleify(self, data):
		assert self.state_size < len(data), "state_size exceeds the total length of the data"
		tuplified = []
		
		for i in range(len(data) - self.state_size):
			chunk = tuple([data[n] for n in range(i, i + self.state_size + 1)])
			tuplified += [(chunk[:-1], chunk[1:])]
		
		return tuplified


	def next(self):
		possible_states = []
		
		if not self.state or self.state not in self.transition_dict:
			possible_states = list(self.transition_dict.keys())
		
		else:
			possible_states = self.transition_dict[self.state]
		self.state = random.choice(possible_states)
		
		return self.state[-1]

	def generate(self, prompt, length=500):
		assert length > len(prompt), "Prompt can't be longer than output_length"
		
		if self.state_size < len(prompt):
			self.state = random.choice(self.transition_dict)
		
		else:
			self.state = prompt[-self.state_size:]
		
		return_seq = prompt
		for _ in range(length - len(prompt)):
			try:
				return_seq += self.next()
		
			except Exception:
				pass
		
		while return_seq.endswith(".") or return_seq.endswith("-"):
			return_seq = return_seq[:-1]
			
			try:
				return_seq += self.next()
			
			except Exception:
				pass
		
		return return_seq


def markovify(markov, subdomain, markovLength, markovQuantity):
	output = []

	for i in range(1, markovLength + 1):

		output_length = len(subdomain)+i
		prompt = subdomain

		j = 1
		while len(prompt) - j > 0 and j < markovLength + 1:

			tempprompt = prompt[:-j]
			for itera in range(0,markovQuantity):
				output.append(markov.generate(tempprompt, output_length))

			j += 1

		for itera in range(0,markovQuantity):
			output.append(markov.generate(prompt, output_length))

	output.append(prompt)
	return output


def init(db, domain, markovState, markovLength, markovQuantity, hideWildcards, threads):
	base = set()

	for row in db.query(Resolution).filter(Resolution.domain == domain, Resolution.isWildcard == False):
		if row.subdomain:
			base.add(row.subdomain)

	for row in db.query(Unresolved).filter(Unresolved.domain == domain):
		if row.subdomain:
			base.add(row.subdomain)

	markov = MarkovChain(markovState)

	for line in base:
		if len(line) > markovState:
			markov.update(line)
	
	baseList = list(base)
	for line in baseList:
		if "." in line:
			a = line.split(".")
			for item in a:
				baseList.append(item)
		if "-" in line:
			a = line.split("-")
			for item in a:
				baseList.append(item)

	baseList = list(set(baseList))
	leaveFlag = True

	if len(baseList) <= 1000:
		print("{0} {1} {2}".format(colored("\n[*]-Performing markov based permutations on", "yellow"), colored("{0}".format(len(baseList)), "cyan"), colored("hostname-parts...", "yellow")))

	else:
		print("{0} {1} {2}".format(colored("\n[*]-Performing markov based permutations on", "yellow"), colored("{0}".format(len(baseList)), "cyan"), colored("hostname-parts in chunks of 1,000...", "yellow")))
	
	numberOfChunks = len(baseList) // 1000 + 1
	baseChunks = utilities.MiscHelpers.chunkify(baseList, 1000)
	iteration = 1

	for baseChunk in baseChunks:
		generators = []
		with ThreadPoolExecutor(max_workers=1) as executor:
			tempMarkov = copy.deepcopy(markov)
			tasks = {executor.submit(markovify, tempMarkov, subdomain, markovLength, markovQuantity): subdomain for subdomain in baseChunk}

			print("{0} {1}".format(colored("\n[*]-Generating markov candidates for chunk", "yellow"), colored(str(iteration) + "/" + str(numberOfChunks), "cyan")))
			try:
				completed = as_completed(tasks)

				if iteration == numberOfChunks:
					leaveFlag = True

				if numberOfChunks == 1:
					completed = tqdm(completed, total=len(baseChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				else:
					completed = tqdm(completed, total=len(baseChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					result = task.result()
					generators.append(result)

			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
				utilities.MiscHelpers.exportFindings(db, domain, [], True)
				executor.shutdown(wait=False)
				exit(-1)

		iteration += 1

		markovified = set()
		for generator in generators:
			for subdomain in generator:
				markovified.add(subdomain)

		markovified.difference_update(base)
		finalMarkovified = []
		for item in markovified:
			finalMarkovified.append((item, "Markov"))

		print("{0} {1} {2} {3}".format(colored("\n[*]-Generated", "yellow"), colored(len(finalMarkovified), "cyan"), colored("markov candidates for chunk", "yellow"), colored(str(iteration - 1) + "/" + str(numberOfChunks), "cyan")))

		identifyWildcards(db, finalMarkovified, domain, threads)
		massResolve(db, finalMarkovified, domain, hideWildcards, threads)