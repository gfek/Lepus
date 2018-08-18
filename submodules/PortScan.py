from IPy import IP
from tqdm import tqdm
from json import dumps
from time import sleep
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures.thread
import socket


def scanTarget(target):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		result = s.connect_ex(target)

		if not result:
			return target

		else:
			return None

	except Exception:
		return None

	finally:
		s.close()


def massConnectScan(targets, threads):
	open_ports = []

	with ThreadPoolExecutor(max_workers=threads) as executor:
		tasks = {executor.submit(scanTarget, target) for target in targets}

		try:
			completed = as_completed(tasks)
			completed = tqdm(completed, total=len(targets), desc="  \__ {0}".format(colored("Progress", 'cyan')), dynamic_ncols=True)

			for task in completed:
				result = task.result()

				if result is not None:
					open_ports.append(result)

		except KeyboardInterrupt:
			executor._threads.clear()
			concurrent.futures.thread._threads_queues.clear()
			print colored("\n\n[*]-Received KeyboardInterrupt. Exiting...\n", 'red')
			sleep(2)
			exit(-1)

	return open_ports


def init(domain, IPs, threads, out_to_json):
	targets = []
	public_IPs = []
	ports = [80, 443, 8080, 8443]

	for ip in IPs:
		if IP(ip).iptype() == "PUBLIC":
			public_IPs.append(ip)

			for port in ports:
				targets.append((ip, port))

	print "{0} {1} {2}".format(colored("\n[*] Scanning", "yellow"), colored(len(public_IPs), "cyan"), colored("unique public IPs for open ports...", "yellow"))

	results = massConnectScan(targets, threads)
	results_json = {}

	for result in results:
		if result[0] in results_json:
			results_json[result[0]].append(result[1])

		else:
			results_json[result[0]] = []
			results_json[result[0]].append(result[1])

	print "    \__ {0} {1}".format(colored("Open ports that were identified:", "yellow"), colored(len(results), "cyan"))

	for key, values in results_json.items():
		print "      \__", colored(key, 'cyan'), ':', ', '.join(colored(str(value), 'yellow') for value in sorted(values))

	if out_to_json:
		try:
			with open('/'.join([domain, "port_scan.json"]), "w") as port_scan_file:
				port_scan_file.write("{0}\n".format(dumps(results_json)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open('/'.join([domain, "port_scan.csv"]), "w") as port_scan_file:
			for key, values in results_json.items():
				port_scan_file.write("{0}|{1}\n".format(key, ','.join(str(value) for value in sorted(values))))

	except OSError:
		pass

	except IOError:
		pass
