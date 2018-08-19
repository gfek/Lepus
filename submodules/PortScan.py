from IPy import IP
from tqdm import tqdm
from json import dumps
from time import sleep
from termcolor import colored
from socket import socket, AF_INET, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures.thread


def scanTarget(target):
	try:
		s = socket(AF_INET, SOCK_STREAM)
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


def init(domain, IPs, port_scan, threads, out_to_json):
	targets = []
	public_IPs = []

	for ip in IPs:
		if IP(ip).iptype() == "PUBLIC":
			public_IPs.append(ip)

	print "{0} {1} {2}".format(colored("\n[*] Scanning", "yellow"), colored(len(public_IPs), "cyan"), colored("unique public IPs for open ports...", "yellow"))

	if port_scan == "small":
		ports = [80, 443]

	elif port_scan == "medium":
		ports = [80, 443, 8000, 8080, 8443]

	elif port_scan == "large":
		ports = [80, 81, 443, 591, 2082, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 55672]

	elif port_scan == "huge":
		ports = [80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 11371, 12443, 16080, 18091, 18092, 20720, 55672]

	else:
		try:
			ports = [int(port.strip()) for port in port_scan.split(',')]

		except Exception:
			print "  \__", colored("Invalid set of ports specified", "red")
			return

	for ip in public_IPs:
		for port in ports:
			targets.append((ip, port))

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
