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
|tqdm|4.28.1|
|requests|2.20.1|
|ipwhois|1.0.0|
|IPy|0.83|
|beautifulsoup4|4.6.3|
|futures|3.2.0|
|dnspython|1.15.0|
|termcolor|1.1.0|

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
                                v2.3.6
[*]-Retrieving DNS Records...
  \__ A: 23.253.135.79
  \__ AAAA: 2001:4802:7901:0:e60a:1375:0:6
  \__ SOA: ns1.p11.dynect.net
  \__ TXT: "v=spf1 mx a:psf.upfronthosting.co.za a:mail.wooz.org ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com ~all"
  \__ TXT: "888acb5757da46ad83b7e341ec544c64"
  \__ TXT: "status-page-domain-verification=9y2klhzbxsgk"
  \__ TXT: "google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA"
  \__ TXT: "google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M"
  \__ TXT: "google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o"
  \__ TXT: "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ"
  \__ NS: ns3.p11.dynect.net
  \__ NS: ns4.p11.dynect.net
  \__ NS: ns1.p11.dynect.net
  \__ NS: ns2.p11.dynect.net
  \__ MX: mail.python.org

[*]-Loading Old Findings...
  \__ Unique subdomains loaded: 81

[*]-Searching Censys...
  \__ No Censys API credentials configured
[*]-Searching CertSpotter...
  \__ Unique subdomains found: 24
[*]-Searching CRT...
  \__ Unique subdomains found: 33
[*]-Searching DNSDB...
  \__ Unique subdomains found: 1
[*]-Searching DNSDumpster...
  \__ Unique subdomains found: 15
[*]-Searching DNSTrails...
  \__ No DNSTrails API key configured
[*]-Searching Entrust Certificates...
  \__ Unique subdomains found: 18
[*]-Searching FindSubdomains...
  \__ Unique subdomains found: 50
[*]-Searching Google Transparency...
  \__ Unique subdomains found: 18
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
  \__ Unique subdomains found: 41

[*]-Loading Wordlist...
  \__ Unique subdomains loaded: 114442

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|████████████████████████████████████████████████████████████████| 6517/6517 [00:11<00:00, 553.53it/s]
    \__ Wildcards that were identified: 2
      \__ *.front.python.org ==> 140.211.10.69
      \__ *.pl.python.org ==> 83.143.134.23

[*]-Attempting to resolve 114475 hostnames, in chunks of 100,000...
  \__ Progress 1/2: 100%|████████████████████████████████████████████████████████████████| 100000/100000 [01:41<00:00, 982.61it/s]
  \__ Progress 2/2: 100%|████████████████████████████████████████████████████████████████| 14475/14475 [00:14<00:00, 999.01it/s]
    \__ Hostnames that were resolved: 60
      \__ blog-ko.python.org (172.217.23.19)
      \__ es.python.org (163.172.190.132)
      \__ mail.python.org (188.166.95.178)
      \__ blog-ro.python.org (172.217.23.19)
      \__ www.es.python.org (163.172.190.132)
      \__ calendario.es.python.org (176.9.11.11)
      \__ console.python.org (23.253.135.79)
      \__ status.python.org (52.215.192.132)
      \__ hg.python.org (104.130.43.97)
      \__ pl.python.org (83.143.134.23)
      \__ staging2.python.org (23.253.135.79)
      \__ packaging.python.org (151.101.16.223)
      \__ blog-tw.python.org (172.217.23.19)
      \__ blog.python.org (151.101.16.175)
      \__ blog-ru.python.org (172.217.23.19)
      \__ www.pl.python.org (83.143.134.23)
      \__ svn.python.org (82.94.164.164)
      \__ blog-pt.python.org (172.217.23.19)
      \__ front.python.org (140.211.10.69)
      \__ documentos-asociacion.es.python.org (176.9.11.11)
      \__ warehouse.python.org (151.101.16.175)
      \__ python.org (23.253.135.79)
      \__ www.python.org (151.101.16.223)
      \__ hg.es.python.org (176.9.11.11)
      \__ socios.es.python.org (163.172.190.132)
      \__ speed.python.org (23.253.135.79)
      \__ discuss.python.org (64.71.168.202)
      \__ blog-fr.python.org (172.217.23.19)
      \__ www.bugs.python.org (151.101.16.223)
      \__ doc.python.org (151.101.16.175)
      \__ warehouse-staging.python.org (151.101.16.175)
      \__ bugs.python.org (46.4.197.70)
      \__ forum.pl.python.org (83.143.134.23)
      \__ docs.python.org (151.101.16.223)
      \__ devguide.python.org (151.101.16.223)
      \__ jobs.python.org (23.253.135.79)
      \__ legacy.python.org (82.94.164.162)
      \__ blog-es.python.org (172.217.23.19)
      \__ cheeseshop.python.org (23.253.135.79)
      \__ ns1.pl.python.org (83.143.134.23)
      \__ pypi.python.org (151.101.16.223)
      \__ buildbot.python.org (140.211.10.71)
      \__ packages.python.org (23.253.135.79)
      \__ wiki.python.org (140.211.10.69)
      \__ openbadges.es.python.org (91.121.173.92)
      \__ testpypi.python.org (151.101.16.175)
      \__ empleo.es.python.org (176.9.11.11)
      \__ uk.python.org (192.30.252.154)
      \__ staging.python.org (23.253.135.79)
      \__ planet.python.org (23.253.135.79)
      \__ blog-ja.python.org (172.217.23.19)
      \__ mail.pl.python.org (46.175.224.26)
      \__ lists.es.python.org (176.9.11.11)
      \__ africa.python.org (34.238.97.72)
      \__ blog-cn.python.org (172.217.23.19)
      \__ wiki-test.python.org (23.253.135.79)
      \__ dinsdale.python.org (82.94.164.162)
      \__ monitoring.python.org (140.211.10.83)
      \__ blog-de.python.org (172.217.23.19)
      \__ pk.python.org (151.101.16.229)

[*]-Performing permutations on 60 resolved hostnames...
  \__ Generated subdomains: 93578

[*]-Checking for wildcards...
  \__ Progress 1/1: 100%|████████████████████████████████████████████████████████████████| 3597/3597 [00:01<00:00, 2342.72it/s]
    \__ Wildcards that were identified: 0

[*]-Attempting to resolve 93647 hostnames...
  \__ Progress 1/1: 100%|████████████████████████████████████████████████████████████████| 93647/93647 [01:52<00:00, 834.56it/s]
    \__ Hostnames that were resolved: 1
      \__ wiki.int.python.org (140.211.10.79)

[*]-Differences from last run - Sat Dec  1 19:25:01 2018
  \__ wiki-test.python.org (23.253.135.79)
  \__ wiki.int.python.org (140.211.10.79)

[*]-Performing RDAP lookups for 24 unique public IPs...
  \__ Progress: 100%|████████████████████████████████████████████████████████████████| 24/24 [00:00<00:00, 46.48it/s]
    \__ Autonomous Systems that were identified:
      \__ ASN: 3265, Prefix: 82.92.0.0/14, Description: XS4ALL-NL Amsterdam, NL
      \__ ASN: 3701, Prefix: 140.211.0.0/16, Description: NERONET - Network for Education and Research in Oregon (NERO), US
      \__ ASN: 6939, Prefix: 64.71.128.0/18, Description: HURRICANE - Hurricane Electric LLC, US
      \__ ASN: 12876, Prefix: 163.172.0.0/16, Description: AS12876, FR
      \__ ASN: 14061, Prefix: 188.166.64.0/18, Description: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN: 14618, Prefix: 34.224.0.0/12, Description: AMAZON-AES - Amazon.com, Inc., US
      \__ ASN: 15169, Prefix: 216.58.198.0/24, Description: GOOGLE - Google LLC, US
      \__ ASN: 15169, Prefix: 172.217.23.0/24, Description: GOOGLE - Google LLC, US
      \__ ASN: 16276, Prefix: 91.121.0.0/16, Description: OVH, FR
      \__ ASN: 16509, Prefix: 52.208.0.0/13, Description: AMAZON-02 - Amazon.com, Inc., US
      \__ ASN: 24940, Prefix: 176.9.0.0/16, Description: HETZNER-AS, DE
      \__ ASN: 24940, Prefix: 46.4.0.0/16, Description: HETZNER-AS, DE
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
      \__ CIDR: 172.217.0.0/16, Identifier: GOOGLE
      \__ CIDR: 176.9.11.0/27, Identifier: HETZNER-fsn1-dc5
      \__ CIDR: 188.166.0.0/17, Identifier: EU-DIGITALOCEAN-NL1
      \__ CIDR: 192.30.252.0/22, Identifier: GITHUB-NET4-1
      \__ CIDR: 216.58.192.0/19, Identifier: GOOGLE
      \__ CIDR: 23.253.134.0/23, Identifier: RACKS-8-1393609936777860
      \__ CIDR: 34.192.0.0/10, Identifier: AT-88-Z
      \__ CIDR: 46.175.224.0/20, Identifier: MAXNET
      \__ CIDR: 46.4.197.64/29, Identifier: HOS-192907
      \__ CIDR: 52.208.0.0/13, Identifier: AMAZON-DUB
      \__ CIDR: 64.71.128.0/18, Identifier: HURRICANE-2
      \__ CIDR: 82.94.164.160/28, Identifier: XS4ALL-CUST
      \__ CIDR: 83.143.128.0/21, Identifier: NFB-KRAKOW-PL
      \__ CIDR: 91.121.160.0/20, Identifier: OVH

```
