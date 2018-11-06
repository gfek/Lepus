from tqdm import tqdm
from time import sleep
from json import dumps
from os.path import join
from termcolor import colored
from socket import gethostbyaddr
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures.thread
import utils


def reverseDNS(IP):
	try:
		return (gethostbyaddr(IP)[0].lower(), IP)

	except Exception:
		return None


def massReverseLookup(IPs, threads):
	hosts = []

	with ThreadPoolExecutor(max_workers=threads) as executor:
		tasks = {executor.submit(reverseDNS, IP) for IP in IPs}

		try:
			completed = as_completed(tasks)
			completed = tqdm(completed, total=len(IPs), desc="  \__ {0}".format(colored("Progress", 'cyan')), dynamic_ncols=True)

			for task in completed:
				result = task.result()

				if result is not None:
					hosts.append(result)

		except KeyboardInterrupt:
			executor._threads.clear()
			concurrent.futures.thread._threads_queues.clear()
			print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
			sleep(2)
			exit(-1)

	return hosts


def init(domain, resolved_public, IPs, threads, out_to_json):
	print "{0} {1} {2}".format(colored("\n[*]-Performing reverse DNS lookups on", "yellow"), colored(len(IPs), "cyan"), colored("unique public IPs...", "yellow"))

	results = massReverseLookup(IPs, threads)
	filtered = utils.filterDomain(domain, [result[0] for result in results])
	diff = []

	for result in results:
		if result[0] in filtered:
			if result[0] not in resolved_public:
				resolved_public[result[0]] = result[1]
				diff.append(result)

	print "    \__ {0} {1}".format(colored("Additional hostnames that were identified:", "yellow"), colored(len(diff), "cyan"))

	for hostname, address in diff:
		print "      \__ {0} {1}".format(colored(hostname, "cyan"), colored(address, 'yellow'))

	if out_to_json:
		try:
			with open(join("results", domain, "resolved_public.json"), "w") as resolved_public_file:
				resolved_public_file.write("{0}\n".format(dumps(resolved_public)))

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

	return resolved_public
