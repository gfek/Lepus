import submodules.RIPE
from termcolor import colored
from ipaddress import ip_address, ip_network
from utilities.DatabaseHelpers import Resolution
from utilities.ScanHelpers import massReverseLookup


def add_cidr_ips(IPs, cidr_str):
    """Add IPs from a CIDR to the set, limiting to /16 or smaller to avoid memory issues."""
    try:
        net = ip_network(cidr_str, strict=False)
        prefix = net.prefixlen
        if prefix < 16:
            print(colored(f"  \__ CIDR {cidr_str} is too large (/{prefix}), expanding only first /16 subnet", "yellow"))
            for subnet in net.subnets(new_prefix=16):
                for ip in subnet.hosts():
                    IPs.add(str(ip))
                    if len(IPs) > 50000:
                        print(colored(f"  \__ Reached 50k IP limit from CIDR expansion", "yellow"))
                        return
        else:
            for ip in net.hosts():
                IPs.add(str(ip))
    except Exception as e:
        print(colored(f"  \__ Error expanding CIDR {cidr_str}: {e}", "red"))


def init(db, domain, ripe, ranges, only_ranges, threads):
    IPs = set()

    if ranges:
        for cidr in ranges.split(","):
            add_cidr_ips(IPs, cidr.strip())

    if ripe:
        ripeCidrs = submodules.RIPE.init(domain)
        for cidr in ripeCidrs:
            add_cidr_ips(IPs, cidr.strip())

    if not only_ranges:
        for row in db.query(Resolution).filter(Resolution.domain == domain):
            try:
                addr = ip_address(row.address)
                if addr.is_global:
                    IPs.add(row.address)
            except ValueError:
                IPs.add(row.address)

    IPs = list(IPs)
    print(colored(f"  \__ Collected {len(IPs)} unique IPs for reverse lookup", "cyan"))
    massReverseLookup(db, domain, IPs, threads)
