[![GitHub License](https://img.shields.io/badge/License-BSD%203--Clause-informational.svg)](https://github.com/GKNSB/Lepus/blob/master/LICENSE)
[![GitHub Python](https://img.shields.io/badge/Python-%3E=%203.5.3-informational.svg)](https://www.python.org/)
[![GitHub Version](https://img.shields.io/badge/Version-3.1.0-yellow.svg)](https://github.com/GKNSB/Lepus)

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
|[DNSDB](http://dnsdb.org/)|No|
|[DNSTrails](https://securitytrails.com/dns-trails/)|Yes|
|[Entrust Certificates](https://www.entrust.com/ct-search/)|No|
|[Findsubdomains](https://findsubdomains.com/)|No|
|[Google Transparency](https://transparencyreport.google.com/)|No|
|[HackerTarget](https://hackertarget.com/)|No|
|[PassiveTotal](https://www.riskiq.com/products/passivetotal/)|Yes|
|[Project Sonar](https://www.rapid7.com/research/project-sonar/)|No|
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

### Portscan
Performs a portscan on well-known web ports. The mode can be enabled with `--portscan` and a specific set of ports can be defined with the `-p` switch. By default `--portscan` scans for default ports 80, 443, 8000, 8080, 8443. Alternatively, use with `--portscan -p small/medium/large/huge` or even `--portscan -p 80,443,444,555` for a custom set of ports. Furthermore, http or https is identified, and the resulting URLs for all identified ports are written in the respective urls.txt in the respective directory for the domain.

|Port set|Ports|
|---|---|
|small|80, 443|
|medium|80, 443, 8000, 8080, 8443|
|large|80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 9000, 9090, 9443|
|huge|80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9943, 9980, 9981, 12443, 16080, 18091, 18092, 20720, 28017|

### Takeover
*(experimental)* Performs several checks on identified domains for potential subdomain-takeover vulnerabilities. The module is enabled with `--takeover` and is executed after all others. If such a vulnerability is identified, the results are printed in the output and in a .csv file in the respective project folder under the directory with the results. Checks are performed for the following services:

* Acquia
* Aftership
* Aha!
* Amazon AWS/S3
* Apigee
* Azure
* Bigcartel
* Bitbucket
* Brightcove
* Campaign Monitor
* Cargo Collective
* Feedpress
* Getresponse
* Ghost[]().io
* Github
* Helpjuice
* Helpscout
* Heroku
* Intercom
* JetBrains
* Maxcdn
* Pantheon
* Readme[]().io
* Simplebooklet
* Smugmug
* Strikingly
* Surge[]().sh
* Teamwork
* Tictail
* Tilda
* Tumblr
* Uptime Robot
* UserVoice
* Vend
* Webflow
* Wishpond
* Wordpress

### Requirements

|Package|Version|
|---|---|
|beautifulsoup4|4.7.1|
|dnspython|1.16.0|
|ipwhois|1.1.0|
|IPy|1.00|
|js2py|0.60|
|requests|2.21.0|
|shodan|1.11.1|
|termcolor|1.1.0|
|tqdm|4.31.1|
|cfscrape|2.0.0|

### Installation

1. Normal installation:
```
$ python3 -m pip install -r requirements.txt
```

2. Preferably install in a virtualenv:
```
$ pyenv virtualenv 3.7.2 lepus
$ pyenv activate lepus
$ pip install -r requirements.txt
```


### Help

```
usage: lepus.py [-h] [-w WORDLIST] [-t THREADS] [-j] [-nc] [-zt] [--permutate]
                [-pw PERMUTATION_WORDLIST] [--reverse] [-r RANGES]
                [--portscan] [-p PORTS] [--takeover] [-v]
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
  --takeover            check identified hosts for potential subdomain take-
                        overs
  -v, --version         show program's version number and exit
```

### Example

`python3 lepus.py python.org --wordlist lists/subdomains.txt --permutate --reverse --portscan -p huge --takeover`
