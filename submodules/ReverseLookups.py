from IPy import IP
from termcolor import colored
from ipaddress import ip_network
from utilities.DatabaseHelpers import Resolution
from utilities.ScanHelpers import massReverseLookup

def init(db, domain, ranges, threads):
	if ranges:
		IPs = []

		for cidr in ranges.split(","):
			for ip in ip_network(str(cidr.strip())):
				IPs.append(str(ip))

	else:
		IPs = set()

		for row in db.query(Resolution).filter(Resolution.domain == domain):
			if "." in row.address:
				if IP(row.address).iptype() == "PUBLIC":
					IPs.add(row.address)

			else:
				IPs.add(row.address)

		IPs = list(IPs)

	massReverseLookup(db, domain, IPs, threads)
