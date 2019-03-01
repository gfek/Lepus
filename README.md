[![GitHub License](https://img.shields.io/badge/License-BSD%203--Clause-informational.svg)](https://github.com/GKNSB/Lepus/blob/master/LICENSE)

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
|[DNSDB](http://www.dnsdb.org/)|No|
|[DNSDumpster](https://dnsdumpster.com/)|No|
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
|shodan|1.10.4|
|termcolor|1.1.0|
|ipwhois|1.0.0|
|requests|2.21.0|
|tqdm|4.29.1|
|IPy|0.83|
|beautifulsoup4|4.7.1|
|futures|3.2.0|
|dnspython|1.16.0|

### Installation

`pip install -r requirements.txt`

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

`python lepus.py python.org --wordlist lists/subdomains.txt --permutate`

```
         ______  _____           ______
 |      |______ |_____) |     | (_____ 
 |_____ |______ |       |_____| ______)
                                v2.3.7
[*]-Retrieving DNS Records...
  \__ A: 23.253.135.79
  \__ AAAA: 2001:4802:7901:0:e60a:1375:0:6
  \__ SOA: ns1.p11.dynect.net
  \__ TXT: "google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o"
  \__ TXT: "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ"
  \__ TXT: "v=spf1 mx a:mail.wooz.org ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com include:mailgun.org ~all"
  \__ TXT: "888acb5757da46ad83b7e341ec544c64"
  \__ TXT: "status-page-domain-verification=9y2klhzbxsgk"
  \__ TXT: "google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA"
  \__ TXT: "google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M"
  \__ NS: ns2.p11.dynect.net
  \__ NS: ns3.p11.dynect.net
  \__ NS: ns4.p11.dynect.net
  \__ NS: ns1.p11.dynect.net
  \__ MX: mail.python.org

[*]-Loading Old Findings...
  \__ Unique subdomains loaded: 84

[*]-Searching Censys...
  \__ No Censys API credentials configured
[*]-Searching CertSpotter...
  \__ Unique subdomains found: 25
[*]-Searching CRT...
  \__ Unique subdomains found: 34
[*]-Searching DNSDB...
  \__ Unique subdomains found: 1
[*]-Searching DNSDumpster...
  \__ Unique subdomains found: 15
[*]-Searching DNSTrails...
  \__ No DNSTrails API key configured
[*]-Searching Entrust Certificates...
  \__ Unique subdomains found: 19
[*]-Searching FindSubdomains...
  \__ Unique subdomains found: 50
[*]-Searching Google Transparency...
  \__ Unique subdomains found: 19
[*]-Searching HackerTarget...
  \__ Unique subdomains found: 16
[*]-Searching PassiveTotal...
  \__ No PassiveTotal API credentials configured
[*]-Searching Riddler...
  \__ No Riddler API credentials configured
[*]-Searching Shodan...
  \__ No Shodan API key configured
[*]-Searching ThreatCrowd...
  \__ Unique subdomains found: 63
[*]-Searching VirusTotal...
  \__ No VirusTotal API key configured
[*]-Searching WaybackMachine...
  \__ Unique subdomains found: 47

[*]-Loading Wordlist...
  \__ Unique subdomains loaded: 114442

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|████████████████████████████████████████| 6517/6517 [00:17<00:00, 381.07it/s]
    \__ Wildcards that were identified: 2
      \__ *.front.python.org ==> 140.211.10.69
      \__ *.pl.python.org ==> 83.143.134.23

[*]-Attempting to resolve 114477 hostnames, in chunks of 100,000...
  \__ Progress 1/2: 100%|████████████████████████████████████████| 100000/100000 [02:28<00:00, 673.62it/s]
  \__ Progress 2/2: 100%|████████████████████████████████████████| 14477/14477 [00:21<00:00, 677.05it/s]
    \__ Hostnames that were resolved: 62
      \__ blog-ko.python.org (216.58.204.19)
      \__ es.python.org (163.172.190.132)
      \__ mail.python.org (188.166.95.178)
      \__ blog-ro.python.org (216.58.204.19)
      \__ www.es.python.org (163.172.190.132)
      \__ calendario.es.python.org (176.9.11.11)
      \__ console.python.org (23.253.135.79)
      \__ status.python.org (52.215.192.132)
      \__ hg.python.org (104.130.43.97)
      \__ pl.python.org (83.143.134.23)
      \__ staging2.python.org (23.253.135.79)
      \__ packaging.python.org (151.101.16.223)
      \__ blog-tw.python.org (216.58.204.19)
      \__ blog.python.org (151.101.16.175)
      \__ blog-ru.python.org (216.58.204.19)
      \__ www.pl.python.org (83.143.134.23)
      \__ svn.python.org (82.94.164.164)
      \__ blog-pt.python.org (216.58.204.19)
      \__ front.python.org (140.211.10.69)
      \__ documentos-asociacion.es.python.org (176.9.11.11)
      \__ warehouse.python.org (151.101.16.175)
      \__ python.org (23.253.135.79)
      \__ www.python.org (151.101.16.223)
      \__ hg.es.python.org (176.9.11.11)
      \__ socios.es.python.org (163.172.190.132)
      \__ speed.python.org (23.253.135.79)
      \__ discuss.python.org (64.71.168.202)
      \__ blog-fr.python.org (216.58.204.19)
      \__ www.bugs.python.org (151.101.16.223)
      \__ doc.python.org (151.101.16.175)
      \__ warehouse-staging.python.org (151.101.16.175)
      \__ bugs.python.org (188.166.48.69)
      \__ forum.pl.python.org (83.143.134.23)
      \__ docs.python.org (151.101.16.223)
      \__ devguide.python.org (151.101.16.223)
      \__ comunidad.es.python.org (51.15.237.199)
      \__ legacy.python.org (82.94.164.162)
      \__ blog-es.python.org (216.58.204.19)
      \__ cheeseshop.python.org (23.253.135.79)
      \__ ns1.pl.python.org (83.143.134.23)
      \__ pypi.python.org (151.101.16.223)
      \__ buildbot.python.org (140.211.10.71)
      \__ packages.python.org (23.253.135.79)
      \__ wiki.python.org (140.211.10.69)
      \__ openbadges.es.python.org (91.121.173.92)
      \__ testpypi.python.org (151.101.16.175)
      \__ empleo.es.python.org (176.9.11.11)
      \__ planet.es.python.org (5.39.90.125)
      \__ jobs.python.org (23.253.135.79)
      \__ uk.python.org (192.30.252.154)
      \__ staging.python.org (23.253.135.79)
      \__ planet.python.org (23.253.135.79)
      \__ blog-ja.python.org (216.58.204.19)
      \__ mail.pl.python.org (46.175.224.26)
      \__ lists.es.python.org (176.9.11.11)
      \__ africa.python.org (34.238.97.72)
      \__ blog-cn.python.org (216.58.204.19)
      \__ wiki-test.python.org (23.253.135.79)
      \__ dinsdale.python.org (82.94.164.162)
      \__ monitoring.python.org (140.211.10.83)
      \__ blog-de.python.org (216.58.204.19)
      \__ pk.python.org (151.101.16.229)

[*]-Performing permutations on 84 hostnames...
  \__ Generated subdomains: 145632

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|████████████████████████████████████████| 17026/17026 [00:32<00:00, 530.54it/s]
    \__ Wildcards that were identified: 0

[*]-Attempting to resolve 145700 hostnames, in chunks of 100,000...
  \__ Progress 1/2: 100%|████████████████████████████████████████| 100000/100000 [03:32<00:00, 470.00it/s]
  \__ Progress 2/2: 100%|████████████████████████████████████████| 45700/45700 [01:36<00:00, 473.45it/s]
    \__ Hostnames that were resolved: 1
      \__ wiki.int.python.org (140.211.10.79)

[*]-Differences since Sun Jan 20 15:33:44 2019:
  \__ wiki.int.python.org (140.211.10.79)

[*]-Performing RDAP lookups for 26 unique public IPs...
  \__ Progress: 100%|████████████████████████████████████████| 26/26 [00:00<00:00, 50.14it/s]
    \__ Autonomous Systems that were identified:
      \__ ASN: 3265, Prefix: 82.92.0.0/14, Description: XS4ALL-NL Amsterdam, NL
      \__ ASN: 3701, Prefix: 140.211.0.0/16, Description: NERONET - Network for Education and Research in Oregon (NERO), US
      \__ ASN: 6939, Prefix: 64.71.128.0/18, Description: HURRICANE - Hurricane Electric LLC, US
      \__ ASN: 12876, Prefix: 163.172.0.0/16, Description: AS12876, FR
      \__ ASN: 12876, Prefix: 51.15.0.0/16, Description: AS12876, FR
      \__ ASN: 14061, Prefix: 188.166.64.0/18, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14061, Prefix: 188.166.0.0/18, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14618, Prefix: 34.224.0.0/12, Description: AMAZON-AES - Amazon.com, Inc., US
      \__ ASN: 15169, Prefix: 216.58.198.0/24, Description: GOOGLE - Google LLC, US
      \__ ASN: 15169, Prefix: 216.58.204.0/23, Description: GOOGLE - Google LLC, US
      \__ ASN: 16276, Prefix: 91.121.0.0/16, Description: OVH, FR
      \__ ASN: 16276, Prefix: 5.39.0.0/17, Description: OVH, FR
      \__ ASN: 16509, Prefix: 52.208.0.0/13, Description: AMAZON-02 - Amazon.com, Inc., US
      \__ ASN: 24940, Prefix: 176.9.0.0/16, Description: HETZNER-AS, DE
      \__ ASN: 27357, Prefix: 23.253.128.0/19, Description: RACKSPACE - Rackspace Hosting, US
      \__ ASN: 27357, Prefix: 104.130.0.0/18, Description: RACKSPACE - Rackspace Hosting, US
      \__ ASN: 35174, Prefix: 83.143.128.0/21, Description: NFB-AS, PL
      \__ ASN: 36459, Prefix: 192.30.252.0/24, Description: GITHUB - GitHub, Inc., US
      \__ ASN: 43171, Prefix: 46.175.224.0/20, Description: MAXNET, PL
    __\__ ASN: 54113, Prefix: 151.101.16.0/22, Description: FASTLY - Fastly, US
    \__ Networks that were identified:
      \__ CIDR: 104.130.0.0/16, Identifier: RACKS-8-NET-16
      \__ CIDR: 140.211.0.0/16, Identifier: NERONET
      \__ CIDR: 151.101.0.0/16, Identifier: SKYCA-3
      \__ CIDR: 163.172.0.0/16, Identifier: ONLINE_NET_DEDICATED_SERVERS
      \__ CIDR: 176.9.11.0/27, Identifier: HETZNER-fsn1-dc5
      \__ CIDR: 188.166.0.0/17, Identifier: EU-DIGITALOCEAN-NL1
      \__ CIDR: 192.30.252.0/22, Identifier: GITHUB-NET4-1
      \__ CIDR: 216.58.192.0/19, Identifier: GOOGLE
      \__ CIDR: 23.253.134.0/23, Identifier: RACKS-8-1393609936777860
      \__ CIDR: 34.192.0.0/10, Identifier: AT-88-Z
      \__ CIDR: 46.175.224.0/20, Identifier: MAXNET
      \__ CIDR: 5.39.80.0/20, Identifier: OVH
      \__ CIDR: 51.15.0.0/16, Identifier: ONLINE_NET_DEDICATED_SERVERS
      \__ CIDR: 52.208.0.0/13, Identifier: AMAZON-DUB
      \__ CIDR: 64.71.128.0/18, Identifier: HURRICANE-2
      \__ CIDR: 82.94.164.160/28, Identifier: XS4ALL-CUST
      \__ CIDR: 83.143.128.0/21, Identifier: NFB-KRAKOW-PL
      \__ CIDR: 91.121.160.0/20, Identifier: OVH

```
