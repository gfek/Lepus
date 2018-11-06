from tqdm import tqdm
from time import sleep
from os.path import join
from termcolor import colored
from socket import socket, AF_INET, SOCK_STREAM
from ssl import create_default_context, CERT_NONE
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures.thread


def urlize(target, domains):
	hosts = [hostname for hostname, address in domains.items() if address == target[0]]

	for host in hosts:
		if target[1] == 80:
			return "http://{0}/".format(host)

		elif target[1] == 443:
			return "https://{0}/".format(host)

		else:
			if target[2]:
				return "https://{0}:{1}/".format(host, target[1])

			else:
				return "http://{0}:{1}/".format(host, target[1])


def scanTarget(target):
	isOpen = False

	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(1)
		result1 = s.connect_ex(target)

		if not result1:
			if target[1] != 80 and target[1] != 443:
				isOpen = True
				context = create_default_context()
				context.check_hostname = False
				context.verify_mode = CERT_NONE
				context.wrap_socket(s)

				return (target[0], target[1], True)

			elif target[1] == 80:
				return (target[0], target[1], False)

			elif target[1] == 443:
				return (target[0], target[1], True)

	except Exception as e:
		if isOpen:
			if "unsupported protocol" in e:
				return (target[0], target[1], True)

			else:
				return (target[0], target[1], False)

		else:
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


def init(resolved, domain, IPs, port_scan, threads):
	targets = []

	print "{0} {1} {2}".format(colored("\n[*] Scanning", "yellow"), colored(len(IPs), "cyan"), colored("unique public IPs for open ports...", "yellow"))

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

	for ip in IPs:
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

	try:
		with open(join("results", domain, "urls.txt"), "w") as port_scan_file:
			for target in results:
				port_scan_file.write("{0}\n".format(urlize(target, resolved)))

	except OSError:
		pass

	except IOError:
		pass
