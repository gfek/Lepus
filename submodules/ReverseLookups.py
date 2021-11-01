import submodules.RIPE 
from termcolor import colored
from ipaddress import ip_address, ip_network
from utilities.DatabaseHelpers import Resolution
from utilities.ScanHelpers import massReverseLookup

def init(db, domain, ripe, ranges, only_ranges, threads):
	IPs = set()

	if ranges:
		for cidr in ranges.split(","):
			for ip in ip_network(str(cidr.strip())):
				IPs.add(str(ip))

	if ripe:
		ripeCidrs = submodules.RIPE.init(domain)

		for cidr in ripeCidrs:
			for ip in ip_network(str(cidr.strip())):
				IPs.add(str(ip))

	if not only_ranges:
		for row in db.query(Resolution).filter(Resolution.domain == domain):
			if "." in row.address:
				if ip_address(row.address).is_global:
					IPs.add(row.address)

			else:
				IPs.add(row.address)

	IPs = list(IPs)
	massReverseLookup(db, domain, IPs, threads)
