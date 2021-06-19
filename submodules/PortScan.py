from time import time
from gc import collect
from termcolor import colored
from ipaddress import ip_address
from collections import OrderedDict
from utilities.MiscHelpers import generateURLs
from utilities.ScanHelpers import massConnectScan
from utilities.DatabaseHelpers import Resolution, OpenPort, URL


def init(db, domain, port_scan, threads):
	targets = set()
	open_ports = OrderedDict()
	timestamp = int(time())

	if not port_scan:
		port_scan = "medium"

	if port_scan == "small":
		ports = [80, 443]

	elif port_scan == "medium":
		ports = [80, 443, 8000, 8080, 8443]

	elif port_scan == "large":
		ports = [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 9000, 9090, 9443]

	elif port_scan == "huge":
		ports = [80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9943, 9980, 9981, 12443, 16080, 18091, 18092, 20720, 28017]

	else:
		ports = [int(port.strip()) for port in port_scan.split(",")]

	for row in db.query(Resolution).filter(Resolution.domain == domain):
		if "." in row.address:
			if ip_address(row.address).is_global:
				for port in ports:
					targets.add((row.address, port))

		else:
			for port in ports:
				targets.add((row.address, port))

	targets = list(targets)
	numberOfUniqueIPs = len(targets) // len(ports)
	massConnectScan(db, domain, numberOfUniqueIPs, targets, threads, timestamp)

	del targets
	collect()

	for row in db.query(OpenPort).filter(OpenPort.domain == domain, OpenPort.timestamp == timestamp).order_by(OpenPort.address, OpenPort.port):
		if row.address in open_ports:
			open_ports[row.address].append((row.port, row.isSSL))

		else:
			open_ports[row.address] = []
			open_ports[row.address].append((row.port, row.isSSL))

	print("    \__ {0}: {1}".format(colored("New ports that were identified as open", "yellow"), colored(db.query(OpenPort).filter(OpenPort.domain == domain, OpenPort.timestamp == timestamp).count(), "cyan")))

	for address, ports in open_ports.items():
		print("      \__ {0}: {1}".format(colored(address, "cyan"), ", ".join(colored(str(port[0]), "yellow") for port in ports)))

	print(colored("\n[*]-Generating URLs based on Port Scan results...", "yellow"))

	generateURLs(db, domain, open_ports, timestamp)

	print("  \__ {0}: {1}".format(colored("New URLs that were generated", "yellow"), colored(db.query(URL).filter(URL.domain == domain, URL.timestamp == timestamp).count(), "cyan")))

	for row in db.query(URL).filter(URL.domain == domain, URL.timestamp == timestamp).order_by(URL.url):
		print("    \__ {0}".format(colored(row.url, "cyan")))
