[![GitHub License](https://img.shields.io/badge/License-BSD%203--Clause-informational.svg)](https://github.com/GKNSB/Lepus/blob/master/LICENSE)
[![GitHub Python](https://img.shields.io/badge/Python-%3E=%203.6-informational.svg)](https://www.python.org/)
[![GitHub Version](https://img.shields.io/badge/Version-3.4.0-green.svg)](https://github.com/GKNSB/Lepus)

# Lepus

**Lepus** is a tool for enumerating subdomains, checking for subdomain takeovers and perform port scans - and boy, is it fast!

#### Basic Usage

```
lepus.py yahoo.com
```

## Summary
* [Enumeration modes](#Enumeration-modes)
* [Subdomain Takeover](#Subdomain-Takeover)
* [Port Scan](#Port-Scan)
* [Installation](#Installation)
* [Arguments](#Arguments)
* [Full command example](#Full-command-example)


## Enumeration modes
The enumeration modes are different ways lepus uses to identify sudomains for a given domain. These modes are:

* [Collectors](#Collectors)
* [Dictionary](#Dictionary)
* [Permutations](#Permutations)
* [Reverse DNS](#ReverseDNS)
* [Markov](#Markov)

Moreover:
* For all methods, lepus checks if the given domain or any generated potential subdomain is a *wildcard* domain or not.
* After identification, lepus collects ASN and network information for the identified domains that resolve to public IP Addresses.


### Collectors
The Collectors mode collects subdomains from the following services:

|Service|API Required|
|---|:---:|
|[Censys](https://censys.io/)|Yes|
|[CertSpotter](https://sslmate.com/certspotter/)|No|
|[CRT](https://crt.sh/)|No|
|[DNSTrails](https://securitytrails.com/dns-trails/)|Yes|
|[FOFA](https://fofa.so/)|Yes|
|[Google Transparency](https://transparencyreport.google.com/)|No|
|[HackerTarget](https://hackertarget.com/)|No|
|[PassiveTotal](https://www.riskiq.com/products/passivetotal/)|Yes|
|[Project Discovery Chaos](https://chaos.projectdiscovery.io/)|Yes|
|[Project Crobat](https://sonar.omnisint.io/)|No|
|[Project Sonar](https://www.rapid7.com/research/project-sonar/)|No|
|[Riddler](https://riddler.io/)|Yes|
|[Shodan](https://www.shodan.io/)|Yes|
|[Spyse](https://api-doc.spyse.com/)|Yes|
|[ThreatCrowd](https://www.threatcrowd.org/)|No|
|[ThreatMiner](https://www.threatminer.org/)|No|
|[VirusTotal](https://www.virustotal.com/)|Yes|
|[Wayback Machine](https://archive.org/web/)|No|
|[ZoomEye](https://www.zoomeye.org/)|Yes|

You can add your API keys in the `config.ini` file.

The Collectors module will run by default on lepus. If you do not want to use the collectors during a lepus run (so that you don't exhaust your API key limits), you can use the `-nc` or `--no-collectors` argument.

### Dictionary
The dictionary mode can be used when you want to provide lepus a list of subdomains. You can use the `-w` or `--wordlist` argument followed by the file. A custom list comes with lepus located at `lists/subdomains.txt`. An example run would be:

```
lepus.py -w lists/subdomains.txt yahoo.com
```

### Permutations
The Permutations mode performs changes on the list of subdomains that have been identified. For each subdomain, a number of permutations will take place based on the `lists/words.txt` file. You can also provide a custom wordlist for permutations with the `-pw` or `--permutation-wordlist` argument, followed by the file name.An example run would be:

```
lepus.py --permutate yahoo.com
```

or

```
lepus.py --permutate -pw customsubdomains.txt yahoo.com
```

### ReverseDNS
The ReverseDNS mode will gather all IP addresses that were resolved and perform a reverse DNS on each one in order to detect more subdomains. For example, if `www.example.com` resolves to `1.2.3.4`, lepus will perform a reverse DNS for `1.2.3.4` and gather any other subdomains belonging to `example.com`, e.g. `www2`,`internal` or `oldsite`.

To run the ReverseDNS module use the `--reverse` argument. Additionally, `--ripe` (or `-ripe`) can be used in order to instruct the module to query the RIPE database using the second level domain for potential network ranges. Moreover, lepus supports the `--ranges` (or `-r`) argument. You can use it to make reverse DNS resolutions against CIDRs that belong to the target domain.

By default this module will take into account all previously identified IPs, then defined ranges, then ranges identified through the RIPE database. In case you only want to run the module against specific or RIPE identified ranges, and not against all already identified IPs, you can use the `--only-ranges` (`-or`) argument.

An example run would be:

```
lepus.py --reverse yahoo.com
```

or

```
lepus.py --reverse -ripe -r 172.216.0.0/16,183.177.80.0/23 yahoo.com
```

or only against the defined or identified from RIPE

```
lepus.py --reverse -or -ripe -r 172.216.0.0/16,183.177.80.0/23 yahoo.com
```

Hint: lepus will identify `ASNs` and `Networks` during enumeration, so you can also use these ranges to identify more subdomains with a subsequent run.

### Markov
With this module, Lepus will utilize Markov chains in order to train itself and then generate subdomain based on the already known ones. The bigger the general surface, the better the tool will be able to train itself and subsequently, the better the results will be.

The module can be activated with the `--markovify` argument. Parameters also include the Markov state size, the maximum length of the generated candidate addition, and the quantity of generated candidates. Predefined values are 3, 5 and 5 respectively. Those arguments can be changed with `-ms` (`--markov-state`), `-ml` (`--markov-length`) and `-mq` (`--markov-quantity`) to meet your needs. Keep in mind that the larger these values are, the more time Lepus will need to generate the candidates.

It has to be noted that different executions of this module might generate different candidates, so feel free to run it a few times consecutively. Keep in mind that the higher the `-ms`, `-ml` and `-mq` values, the more time will be needed for candidate generation.

```
lepus.py --markovify yahoo.com
```

or

```
lepus.py --markovify -ms 5 -ml 10 -mq 10
```

## Subdomain Takeover
Lepus has a list of signatures in order to identify if a domain can be taken over. You can use it by providing the `--takeover` argument. This module also supports Slack notifications, once a potential takeover has been identified, by adding a Slack token in the `config.ini` file. The checks are made against the following services:

* Acquia
* Activecampaign
* Aftership
* Aha!
* Airee
* Amazon AWS/S3
* Apigee
* Azure
* Bigcartel
* Bitbucket
* Brightcove
* Campaign Monitor
* Cargo Collective
* Desk
* Feedpress
* Fly[]().io
* Getresponse
* Ghost[]().io
* Github
* Hatena
* Helpjuice
* Helpscout
* Heroku
* Instapage
* Intercom
* JetBrains
* Kajabi
* Kayako
* Launchrock
* Mashery
* Maxcdn
* Moosend
* Ning
* Pantheon
* Pingdom
* Readme[]().io
* Simplebooklet
* Smugmug
* Statuspage
* Strikingly
* Surge[]().sh
* Surveygizmo
* Tave
* Teamwork
* Thinkific
* Tictail
* Tilda
* Tumblr
* Uptime Robot
* UserVoice
* Vend
* Webflow
* Wishpond
* Wordpress
* Zendesk


## Port Scan
The port scan module will check open ports against a target and log them in the results. You can use the `--portscan` argument which by default will scan ports 80, 443, 8000, 8080, 8443. You can also use custom ports or choose a predefined set of ports.

|Ports set|Ports|
|---|---|
|small|80, 443|
|medium (default)|80, 443, 8000, 8080, 8443|
|large|80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 9000, 9090, 9443|
|huge|80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9943, 9980, 9981, 12443, 16080, 18091, 18092, 20720, 28017|

An example run would be:

```
lepus.py --portscan yahoo.com
```

or

```
lepus.py --portscan -p huge yahoo.com
```

or

```
lepus.py --portscan -p 80,443,8082,65123 yahoo.com
```


## Installation

1. Normal installation:

	```
	$ python3.7 -m pip install -r requirements.txt
	```

2. Preferably install in a virtualenv:

	```
	$ pyenv virtualenv 3.7.4 lepus
	$ pyenv activate lepus
	$ pip install -r requirements.txt
	```

3. Installing latest python on debian:

	```
	$ apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget
	$ curl -O https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tar.xz
	$ tar -xf Python-3.7.4.tar.xz
	$ cd Python-3.7.4
	$ ./configure --enable-optimizations --enable-loadable-sqlite-extensions
	$ make
	$ make altinstall
	```


## Arguments

```
usage: lepus.py [-h] [-w WORDLIST] [-hw] [-t THREADS] [-nc] [-zt]
                [--permutate] [-pw PERMUTATION_WORDLIST] [--reverse]
                [-r RANGES] [--portscan] [-p PORTS] [--takeover] [--markovify]
                [-ms MARKOV_STATE] [-ml MARKOV_LENGTH] [-mq MARKOV_QUANTITY]
                [-f] [-v]
                domain

Infrastructure OSINT

positional arguments:
  domain                domain to search

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        wordlist with subdomains
  -hw, --hide-wildcards
                        hide wildcard resolutions
  -t THREADS, --threads THREADS
                        number of threads [default is 100]
  -nc, --no-collectors  skip passive subdomain enumeration
  -zt, --zone-transfer  attempt to zone transfer from identified name servers
  --permutate           perform permutations on resolved domains
  -pw PERMUTATION_WORDLIST, --permutation-wordlist PERMUTATION_WORDLIST
                        wordlist to perform permutations with [default is
                        lists/words.txt]
  --reverse             perform reverse dns lookups on resolved public IP
                        addresses
  -ripe, --ripe         query ripe database with the 2nd level domain 
                        for networks to be used for reverse lookups
  -r RANGES, --ranges RANGES
                        comma seperated ip ranges to perform reverse dns
                        lookups on
  -or, --only-ranges    use only ranges provided with -r or -ripe and not all
                        previously identified IPs
  --portscan            scan resolved public IP addresses for open ports
  -p PORTS, --ports PORTS
                        set of ports to be used by the portscan module
                        [default is medium]
  --takeover            check identified hosts for potential subdomain take-
                        overs
  --markovify           use markov chains to identify more subdomains
  -ms MARKOV_STATE, --markov-state MARKOV_STATE
                        markov state size [default is 3]
  -ml MARKOV_LENGTH, --markov-length MARKOV_LENGTH
                        max length of markov substitutions [default is 5]
  -mq MARKOV_QUANTITY, --markov-quantity MARKOV_QUANTITY
                        max quantity of markov results per candidate length
                        [default is 5]
  -f, --flush           purge all records of the specified domain from the
                        database
  -v, --version         show program's version number and exit
```

## Full command example
The following, is an example run with all available active arguments:
```
./lepus.py python.org --wordlist lists/subdomains.txt --permutate -pw ~/mypermsword.lst --reverse -ripe -r 10.11.12.0/24 --portscan -p huge --takeover --markovify -ms 3 -ml 10 -mq 10
```

The following command flushes all database entries for a specific domain:
```
./lepus.py python.org --flush
```
