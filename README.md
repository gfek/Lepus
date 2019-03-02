[![GitHub License](https://img.shields.io/badge/License-BSD%203--Clause-informational.svg)](https://github.com/GKNSB/Lepus/blob/master/LICENSE)
[![GitHub Python](https://img.shields.io/badge/Python-3.5.3-yellow.svg)](https://www.python.org/)
[![GitHub Version](https://img.shields.io/badge/Version-3.0.1-success.svg)](https://github.com/GKNSB/Lepus)

## Lepus
**Sub-domain finder**

**Lepus** is a utility for identifying and collecting subdomains for a given domain. Subdomain discovery is a crucial part during the reconnaissance phase. It uses four (4) modes:

* Services (Collecting subdomains from the below services)
* Dictionary mode for identifying domains (optional)
* Permutations on discovered subdomains (optional)
* Reverse DNS lookups on identified public IPs (optional)

### Wildcard Identification

The utility checks if the given domain or any generated subdomain is a *wildcard* domain or not.

### RDAP Lookups

The utility collects ASN and network information for the identified domains that resolve to public IP Addresses.

### Services

The utility is collecting data from the following services:

|Service|API Required|
|---|:---:|
|[Censys](https://censys.io/)|Yes|
|[CertSpotter](https://sslmate.com/certspotter/)|No|
|[CRT](https://crt.sh/)|No|
|[DNSTrails](https://securitytrails.com/dns-trails/)|Yes|
|[Entrust Certificates](https://www.entrust.com/ct-search/)|No|
|[Findsubdomains](https://findsubdomains.com/)|No|
|[Google Transparency](https://transparencyreport.google.com/)|No|
|[HackerTarget](https://hackertarget.com/)|No|
|[PassiveTotal](https://www.riskiq.com/products/passivetotal/)|Yes|
|[Riddler](https://riddler.io/)|Yes|
|[Shodan](https://www.shodan.io/)|Yes|
|[ThreatCrowd](https://www.threatcrowd.org/)|No|
|[VirusTotal](https://www.virustotal.com/)|Yes|
|[Wayback Machine](https://archive.org/web/)|No|

In a case that you want to consume services that support API keys then you have to place your API keys in the `config.ini` file.

```
[Cencys]
UID=<YourCensysUID>
SECRET=<YourCensysSecret>

[DNSTrails]
DNSTrail_API_KEY=<YourDNSTrailsAPIKey>

[PassiveTotal]
PT_KEY=<YourPassiveTotalKey>
PT_SECRET=<YourPassiveTotalSecret>

[Riddler]
RIDDLER_USERNAME=<YourRiddlerUsername>
RIDDLER_PASSWORD=<YourRiddlerPassword>

[Shodan]
SHODAN_API_KEY=<YourShodanAPI>

[VirusTotal]
VT_API_KEY=<YourVirusTotalAPIKey>
```

### Dictionary Mode

A file can be given as an input to the `-w (--wordlist)` switch for performing a dictionary discovery. Forward DNS lookup is performed during this time for identifying subdomains.

### Permutations Mode

Permutations mode is enabled with the `--permutate` switch. A file can be given as an input to the `-pw (--permutation-wordlist)` switch for performing the permutations (default list is lists/words.txt). During this time, a number of permutations are applied on the already discovered subdomains.

### Reverse Mode

Reverse Mode is enabled by providing the `--reverse` switch. This mode will perform reverse DNS lookups on the identified public IPs.
IP ranges can also be provided using the `--ranges` switch.

### Requirements

|Package|Version|
|---|---|
|beautifulsoup4|4.7.1|
|dnspython|1.16.0|
|ipwhois|1.1.0|
|IPy|1.00|
|requests|2.21.0|
|shodan|1.11.1|
|termcolor|1.1.0|
|tqdm|4.31.1|

### Installation

`python3 -m pip install -r requirements.txt`

### Help

```
usage: lepus.py [-h] [-w WORDLIST] [-t THREADS] [-j] [-nc] [-zt] [--permutate]
                [-pw PERMUTATION_WORDLIST] [--reverse] [-r RANGES]
                [--portscan] [-p PORTS] [-v]
                domain

Infrastructure OSINT

positional arguments:
  domain                domain to search

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        wordlist with subdomains
  -t THREADS, --threads THREADS
                        number of threads [default is 100]
  -j, --json            output to json as well [default is '|' delimited csv]
  -nc, --no-collectors  skip passive subdomain enumeration
  -zt, --zone-transfer  attempt to zone transfer from identified name servers
  --permutate           perform permutations on resolved domains
  -pw PERMUTATION_WORDLIST, --permutation-wordlist PERMUTATION_WORDLIST
                        wordlist to perform permutations with [default is
                        lists/words.txt]
  --reverse             perform reverse dns lookups on resolved public IP
                        addresses
  -r RANGES, --ranges RANGES
                        comma seperated ip ranges to perform reverse dns
                        lookups on
  --portscan            scan resolved public IP addresses for open ports
  -p PORTS, --ports PORTS
                        set of ports to be used by the portscan module
                        [default is medium]
  -v, --version         show program's version number and exit
```

### Example

`python3 lepus.py python.org --wordlist lists/subdomains.txt --permutate`

```
         ______  _____           ______
 |      |______ |_____) |     | (_____
 |_____ |______ |       |_____| ______)
                                v3.0.1
[*]-Retrieving DNS Records...
  \__ NS: ns2.p11.dynect.net
  \__ NS: ns4.p11.dynect.net
  \__ NS: ns1.p11.dynect.net
  \__ NS: ns3.p11.dynect.net
  \__ TXT: "v=spf1 mx a:mail.wooz.org ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com include:mailgun.org ~all"
  \__ TXT: "google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M"
  \__ TXT: "888acb5757da46ad83b7e341ec544c64"
  \__ TXT: "status-page-domain-verification=9y2klhzbxsgk"
  \__ TXT: "google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o"
  \__ TXT: "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ"
  \__ TXT: "google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA"
  \__ A: 45.55.99.72
  \__ SOA: ns1.p11.dynect.net
  \__ MX: mail.python.org

[*]-Loading Old Findings...
  \__ Unique subdomains loaded: 86

[*]-Searching Censys...
  \__ No Censys API credentials configured
[*]-Searching CertSpotter...
  \__ Unique subdomains found: 30
[*]-Searching CRT...
  \__ Unique subdomains found: 39
[*]-Searching DNSTrails...
  \__ No DNSTrails API key configured
[*]-Searching Entrust Certificates...
  \__ Unique subdomains found: 24
[*]-Searching FindSubdomains...
  \__ Unique subdomains found: 30
[*]-Searching Google Transparency...
  \__ Unique subdomains found: 24
[*]-Searching HackerTarget...
  \__ Unique subdomains found: 16
[*]-Searching PassiveTotal...
  \__ No PassiveTotal API credentials configured
[*]-Searching Riddler...
  \__ No Riddler API credentials configured
[*]-Searching Shodan...
  \__ No Shodan API key configured
[*]-Searching ThreatCrowd...
  \__ Unique subdomains found: 65
[*]-Searching VirusTotal...
  \__ No VirusTotal API key configured
[*]-Searching WaybackMachine...
  \__ Unique subdomains found: 46

[*]-Loading Wordlist...
  \__ Unique subdomains loaded: 484700

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|########################################| 40002/40002 [01:46<00:00, 377.28it/s]
    \__ Wildcards that were identified: 1
      \__ *.pl.python.org ==> 83.143.134.23

[*]-Attempting to resolve 484735 hostnames, in chunks of 100,000...
  \__ Progress 1/5: 100%|########################################| 100000/100000 [01:46<00:00, 935.49it/s]
  \__ Progress 2/5: 100%|########################################| 100000/100000 [01:48<00:00, 922.52it/s]
  \__ Progress 3/5: 100%|########################################| 100000/100000 [01:46<00:00, 936.63it/s]
  \__ Progress 4/5: 100%|########################################| 100000/100000 [01:47<00:00, 927.54it/s]
  \__ Progress 5/5: 100%|########################################|   84735/84735 [01:30<00:00, 934.85it/s]
    \__ Hostnames that were resolved: 61
      \__ python.org (45.55.99.72)
      \__ blog.python.org (151.101.16.175)
      \__ packages.python.org (45.55.99.72)
      \__ devguide.python.org (151.101.120.223)
      \__ blog-es.python.org (172.217.22.83)
      \__ blog-pt.python.org (172.217.22.83)
      \__ www.es.python.org (163.172.190.132)
      \__ mail.pl.python.org (46.175.224.26)
      \__ warehouse.python.org (151.101.120.175)
      \__ jobs.python.org (45.55.99.72)
      \__ doc.python.org (151.101.120.175)
      \__ blog-cn.python.org (172.217.22.83)
      \__ blog-ja.python.org (172.217.22.83)
      \__ packaging.python.org (151.101.120.223)
      \__ comunidad.es.python.org (51.15.237.199)
      \__ socios.es.python.org (163.172.190.132)
      \__ docs.python.org (151.101.120.223)
      \__ uk.python.org (206.189.73.52)
      \__ ns1.pl.python.org (83.143.134.23)
      \__ discuss.python.org (64.71.168.202)
      \__ buildbot.python.org (140.211.10.71)
      \__ www.pl.python.org (83.143.134.23)
      \__ documentos-asociacion.es.python.org (176.9.11.11)
      \__ empleo.es.python.org (176.9.11.11)
      \__ pl.python.org (83.143.134.23)
      \__ legacy.python.org (82.94.164.162)
      \__ www.python.org (151.101.120.223)
      \__ blog-de.python.org (172.217.22.83)
      \__ staging.python.org (34.206.36.121)
      \__ openbadges.es.python.org (91.121.173.92)
      \__ pk.python.org (151.101.120.229)
      \__ africa.python.org (34.238.97.72)
      \__ blog-ko.python.org (172.217.22.83)
      \__ wiki.python.org (140.211.10.69)
      \__ lists.es.python.org (176.9.11.11)
      \__ bugs.python.org (188.166.48.69)
      \__ pycon-archive.python.org (185.199.111.153)
      \__ forum.pl.python.org (83.143.134.23)
      \__ planet.python.org (45.55.99.72)
      \__ blog-ro.python.org (172.217.22.83)
      \__ community.uk.python.org (185.199.108.153)
      \__ es.python.org (163.172.190.132)
      \__ front.python.org (140.211.10.69)
      \__ status.python.org (52.215.192.132)
      \__ planet.es.python.org (5.39.90.125)
      \__ hg.python.org (138.197.54.234)
      \__ hg.es.python.org (176.9.11.11)
      \__ blog-ru.python.org (172.217.22.83)
      \__ pypi.python.org (151.101.120.223)
      \__ mail.python.org (188.166.95.178)
      \__ speed.python.org (68.183.149.166)
      \__ dinsdale.python.org (82.94.164.162)
      \__ warehouse-staging.python.org (151.101.16.175)
      \__ blog-fr.python.org (172.217.22.83)
      \__ monitoring.python.org (140.211.10.83)
      \__ calendario.es.python.org (176.9.11.11)
      \__ console.python.org (45.55.99.72)
      \__ testpypi.python.org (151.101.16.175)
      \__ cheeseshop.python.org (45.55.99.72)
      \__ svn.python.org (82.94.164.164)
      \__ blog-tw.python.org (172.217.22.83)

[*]-Performing permutations on 86 hostnames...
  \__ Generated subdomains: 151449

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|########################################| 18546/18546 [00:40<00:00, 458.13it/s]
    \__ Wildcards that were identified: 1
      \__ *.front.python.org ==> 140.211.10.69

[*]-Attempting to resolve 151519 hostnames, in chunks of 100,000...
  \__ Progress 1/2: 100%|########################################| 100000/100000 [02:59<00:00, 556.77it/s]
  \__ Progress 2/2: 100%|########################################|   51519/51519 [01:33<00:00, 553.66it/s]
    \__ Hostnames that were resolved: 1
      \__ wiki.int.python.org (140.211.10.79)

[*]-Differences since Mon Feb 18 01:27:29 2019:
  \__ wiki.int.python.org (140.211.10.79)

[*]-Performing RDAP lookups for 31 unique public IPs...
  \__ Progress: 100%|########################################| 31/31 [00:00<00:00, 32.66it/s]
    \__ Autonomous Systems that were identified:
      \__ ASN: 3265, Prefix: 82.92.0.0/14, Description: XS4ALL-NL Amsterdam, NL
      \__ ASN: 3701, Prefix: 140.211.0.0/16, Description: NERONET - Network for Education and Research in Oregon (NERO), US
      \__ ASN: 6939, Prefix: 64.71.128.0/18, Description: HURRICANE - Hurricane Electric LLC, US
      \__ ASN: 12876, Prefix: 51.15.0.0/16, Description: AS12876, FR
      \__ ASN: 12876, Prefix: 163.172.0.0/16, Description: AS12876, FR
      \__ ASN: 14061, Prefix: 159.89.176.0/20, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 188.166.0.0/18, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 138.197.52.0/22, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 45.55.96.0/22, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 206.189.64.0/20, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 188.166.64.0/18, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14618, Prefix: 34.224.0.0/12, Description: AMAZON-AES - Amazon.com, Inc., US
      \__ ASN: 14618, Prefix: 34.192.0.0/12, Description: AMAZON-AES - Amazon.com, Inc., US
      \__ ASN: 15169, Prefix: 172.217.22.0/24, Description: GOOGLE - Google LLC, US
      \__ ASN: 16276, Prefix: 5.39.0.0/17, Description: OVH, FR
      \__ ASN: 16276, Prefix: 91.121.0.0/16, Description: OVH, FR
      \__ ASN: 16509, Prefix: 52.208.0.0/13, Description: AMAZON-02 - Amazon.com, Inc., US
      \__ ASN: 24940, Prefix: 176.9.0.0/16, Description: HETZNER-AS, DE
      \__ ASN: 35174, Prefix: 83.143.128.0/21, Description: NFB-AS, PL
      \__ ASN: 43171, Prefix: 46.175.224.0/20, Description: MAXNET, PL
      \__ ASN: 54113, Prefix: 151.101.120.0/22, Description: FASTLY - Fastly, US
      \__ ASN: 54113, Prefix: 151.101.16.0/22, Description: FASTLY - Fastly, US
      \__ ASN: 54113, Prefix: 185.199.111.0/24, Description: FASTLY - Fastly, US
    __\__ ASN: 54113, Prefix: 185.199.110.0/24, Description: FASTLY - Fastly, US
   \
    \__ Networks that were identified:
      \__ CIDR: 138.197.0.0/16, Identifier: DIGITALOCEAN-16
      \__ CIDR: 140.211.0.0/16, Identifier: NERONET
      \__ CIDR: 151.101.0.0/16, Identifier: SKYCA-3
      \__ CIDR: 159.89.0.0/16, Identifier: DIGITALOCEAN-21
      \__ CIDR: 163.172.0.0/16, Identifier: ONLINE_NET_DEDICATED_SERVERS
      \__ CIDR: 172.217.0.0/16, Identifier: GOOGLE
      \__ CIDR: 176.9.11.0/27, Identifier: HETZNER-fsn1-dc5
      \__ CIDR: 185.199.108.0/22, Identifier: US-GITHUB-20170413
      \__ CIDR: 188.166.0.0/17, Identifier: EU-DIGITALOCEAN-NL1
      \__ CIDR: 206.189.0.0/16, Identifier: DIGITALOCEAN-30
      \__ CIDR: 34.192.0.0/10, Identifier: AT-88-Z
      \__ CIDR: 45.55.0.0/16, Identifier: DIGITALOCEAN-11
      \__ CIDR: 46.175.224.0/20, Identifier: MAXNET
      \__ CIDR: 5.39.80.0/20, Identifier: OVH
      \__ CIDR: 51.15.0.0/16, Identifier: ONLINE_NET_DEDICATED_SERVERS
      \__ CIDR: 52.208.0.0/13, Identifier: AMAZON-DUB
      \__ CIDR: 64.71.128.0/18, Identifier: HURRICANE-2
      \__ CIDR: 82.94.164.160/28, Identifier: XS4ALL-CUST
      \__ CIDR: 83.143.128.0/21, Identifier: NFB-KRAKOW-PL
      \__ CIDR: 91.121.160.0/20, Identifier: OVH

```
