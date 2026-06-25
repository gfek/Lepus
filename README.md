[![GitHub License](https://img.shields.io/badge/License-BSD%203--Clause-informational.svg)](https://github.com/GKNSB/Lepus/blob/master/LICENSE)
[![GitHub Python](https://img.shields.io/badge/Python-%3E=%203.8-informational.svg)](https://www.python.org/)
[![GitHub Version](https://img.shields.io/badge/Version-3.6.0-green.svg)](https://github.com/GKNSB/Lepus)

# Lepus - The Ultimate Reconnaissance Tool

**Lepus** is a powerful and comprehensive tool for subdomain enumeration, vulnerability scanning, and bug hunting. It's designed to provide an overpowered reconnaissance capability with smart findings and advanced features to cover all aspects of wildcard domain recon.

#### Basic Usage

```
lepus.py example.com
```

## Summary
* [Enumeration modes](#Enumeration-modes)
* [Subdomain Takeover](#Subdomain-Takeover)
* [Port Scan](#Port-Scan)
* [Intelligence and Analysis Engine](#Intelligence-and-Analysis-Engine)
* [Custom Scripting for Bug Discovery](#Custom-Scripting-for-Bug-Discovery)
* [Change Detection](#Change-Detection)
* [Notifications](#Notifications)
* [Reporting](#Reporting)
* [Installation](#Installation)
* [Arguments](#Arguments)
* [Full command example](#Full-command-example)


## Enumeration modes
The enumeration modes are different ways lepus uses to identify subdomains for a given domain. These modes are:

* [Collectors](#Collectors)
* [Dictionary](#Dictionary)
* [Permutations](#Permutations)
* [Reverse DNS](#ReverseDNS)
* [Markov](#Markov)

Moreover:
* For all methods, lepus checks if the given domain or any generated potential subdomain is a *wildcard* domain or not.
* After identification, lepus collects ASN and network information for the identified domains that resolve to public IP Addresses.
* Collectors run **concurrently** using asyncio for maximum performance.


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
|[PDChaos](https://chaos.projectdiscovery.io/)|Yes|
|[Shodan](https://www.shodan.io/)|Yes|
|[Spyse](https://api-doc.spyse.com/)|Yes|
|[VirusTotal](https://www.virustotal.com/)|Yes|
|[Wayback Machine](https://archive.org/web/)|No|
|[ZoomEye](https://www.zoomeye.org/)|Yes|
|[Subfinder](https://github.com/projectdiscovery/subfinder)|No (External Tool)|
|[Amass](https://github.com/owasp-amass/amass)|No (External Tool)|

You can add your API keys in the `config.ini` file.

The Collectors module will run by default on lepus. If you do not want to use the collectors during a lepus run (so that you don't exhaust your API key limits), you can use the `-nc` or `--no-collectors` argument.

### Dictionary
The dictionary mode can be used when you want to provide lepus a list of subdomains. You can use the `-w` or `--wordlist` argument followed by the file. A custom list comes with lepus located at `lists/subdomains.txt`. An example run would be:

```
lepus.py -w lists/subdomains.txt example.com
```

### Permutations
The Permutations mode performs changes on the list of subdomains that have been identified. For each subdomain, a number of permutations will take place based on the `lists/words.txt` file. You can also provide a custom wordlist for permutations with the `-pw` or `--permutation-wordlist` argument, followed by the file name.An example run would be:

```
lepus.py --permutate example.com
```

or

```
lepus.py --permutate -pw customsubdomains.txt example.com
```

### ReverseDNS
The ReverseDNS mode will gather all IP addresses that were resolved and perform a reverse DNS on each one in order to detect more subdomains. For example, if `www.example.com` resolves to `1.2.3.4`, lepus will perform a reverse DNS for `1.2.3.4` and gather any other subdomains belonging to `example.com`, e.g. `www2`,`internal` or `oldsite`.

To run the ReverseDNS module use the `--reverse` argument. Additionally, `--ripe` (or `-ripe`) can be used in order to instruct the module to query the RIPE database using the second level domain for potential network ranges. Moreover, lepus supports the `--ranges` (or `-r`) argument. You can use it to make reverse DNS resolutions against CIDRs that belong to the target domain.

By default this module will take into account all previously identified IPs, then defined ranges, then ranges identified through the RIPE database. In case you only want to run the module against specific or RIPE identified ranges, and not against all already identified IPs, you can use the `--only-ranges` (`-or`) argument.

An example run would be:

```
lepus.py --reverse example.com
```

or

```
lepus.py --reverse -or -ripe -r 172.216.0.0/16,183.177.80.0/23 example.com
```

Hint: lepus will identify `ASNs` and `Networks` during enumeration, so you can also use these ranges to identify more subdomains with a subsequent run.

### Markov
With this module, Lepus will utilize Markov chains in order to train itself and then generate subdomain based on the already known ones. The bigger the general surface, the better the tool will be able to train itself and subsequently, the better the results will be.

The module can be activated with the `--markovify` argument. Parameters also include the Markov state size, the maximum length of the generated candidate addition, and the quantity of generated candidates. Predefined values are 3, 5 and 5 respectively. Those arguments can be changed with `-ms` (`--markov-state`), `-ml` (`--markov-length`) and `-mq` (`--markov-quantity`) to meet your needs. Keep in mind that the larger these values are, the more time Lepus will need to generate the candidates.

It has to be noted that different executions of this module might generate different candidates, so feel free to run it a few times consecutively. Keep in mind that the higher the `-ms`, `-ml` and `-mq` values, the more time will be needed for candidate generation.

```
lepus.py --markovify example.com
```

or

```
lepus.py --markovify -ms 5 -ml 10 -mq 10
```

## Subdomain Takeover
Lepus has a list of signatures in order to identify if a domain can be taken over. You can use it by providing the `--takeover` argument. This module also supports Slack and Telegram notifications, once a potential takeover has been identified, by passing `--slack-token`/`--slack-channel` or `--telegram-token`/`--telegram-chat` arguments. The checks are made against the following services:

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
lepus.py --portscan example.com
```

or

```
lepus.py --portscan -p huge example.com
```

or

```
lepus.py --portscan -p 80,443,8082,65123 example.com
```

## Intelligence and Analysis Engine

Lepus now includes advanced intelligence and analysis capabilities to help you identify potential vulnerabilities and interesting targets.

### Technology Profiling
This module identifies the technologies running on each resolved subdomain by analyzing HTTP headers and HTML content. This helps in understanding the tech stack and potential attack surface.

To use this module, use the `--tech-profile` argument:

```
lepus.py --tech-profile example.com
```

### Vulnerability Scanning
Lepus integrates with Nuclei to perform automated vulnerability scanning on resolved subdomains. This helps in identifying known vulnerabilities in the identified technologies.

To use this module, ensure Nuclei is installed and in your PATH, then use the `--vuln-scan` argument:

```
lepus.py --vuln-scan example.com
```

### Interesting Subdomain Detection
This module flags subdomains that are more likely to be interesting from a security perspective, such as development, staging, or administrative panels. It uses a predefined list of keywords to identify such subdomains.

To use this module, use the `--interesting` argument:

```
lepus.py --interesting example.com
```

### Correlated Threat Intelligence
This is the most powerful feature of Lepus. The intelligence engine correlates all findings from the other modules to create a prioritized threat report. It automatically identifies high-risk assets by connecting interesting subdomains, technologies, vulnerabilities, and sensitive file exposures.

Crucially, it integrates the **CISA Known Exploited Vulnerabilities (KEV) catalog** to immediately escalate any actively exploited vulnerability to a **CRITICAL** finding.

To use this module, use the `--intelligence` argument. This will generate a `[domain]_Threat_Report.md` file in the findings directory.

```
lepus.py --intelligence example.com
```

## Custom Scripting for Bug Discovery

Lepus now includes custom scripts to automate the discovery of common bug patterns.

### Sensitive File Scanner
This module scans for exposed sensitive files, such as configuration files, backup files, and other potentially confidential information. It checks for a comprehensive list of common sensitive file extensions and paths.

To use this module, use the `--sensitive-scan` argument:

```
lepus.py --sensitive-scan example.com
```

### Directory and File Brute-forcing
This module systematically uncovers hidden directories and files, undocumented API endpoints, backup files, and misconfigurations by performing content discovery using `ffuf`. This significantly expands the attack surface.

To use this module, ensure `ffuf` is installed and in your PATH, and you have a suitable wordlist (e.g., from SecLists). Use the `--dir-brute` argument:

```
lepus.py --dir-brute example.com
```

## Change Detection

Lepus can detect changes between consecutive scans of the same domain. It takes a snapshot of resolved and unresolved subdomains on each scan, then on subsequent runs computes the difference (newly resolved, newly unresolved, and newly discovered subdomains).

To use this module, use the `--diff` argument:

```
lepus.py --diff example.com
```

Differences are also included in Telegram/Slack notifications when configured.

## Notifications

Lepus supports sending results via Slack and Telegram after a scan completes.

### Slack Notifications
To send findings to a Slack channel, pass the `--slack-token` and `--slack-channel` arguments:

```
lepus.py --slack-token xoxb-xxx --slack-channel #alerts example.com
```

### Telegram Notifications
To send findings via Telegram, pass the `--telegram-token` and `--telegram-chat` arguments:

```
lepus.py --telegram-token 123:abc --telegram-chat -123456789 example.com
```
When used with `--diff`, only changes are included in the notification message.

## Reporting

Lepus can generate comprehensive reports of its findings in various formats.

### JSON Report
Generates a JSON report containing all the findings from the enumeration and analysis process.

To generate a JSON report, use the `--json-report` argument:

```
lepus.py --json-report example.com
```

### HTML Report
Generates an HTML report for easy viewing in a web browser, summarizing all the findings.

To generate an HTML report, use the `--html-report` argument:

```
lepus.py --html-report example.com
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
                [--permutate] [-pw PERMUTATION_WORDLIST] [--reverse] [-ripe]
                [-r RANGES] [-or] [--portscan] [-p PORTS] [--takeover]
                [--tech-profile] [--vuln-scan] [--interesting]
                [--sensitive-scan] [--dir-brute] [--intelligence]
                [--markovify] [-ms MARKOV_STATE] [-ml MARKOV_LENGTH]
                [-mq MARKOV_QUANTITY] [-f] [--json-report] [--html-report]
                [--diff] [--telegram-token TELEGRAM_TOKEN]
                [--telegram-chat TELEGRAM_CHAT_ID]
                [--slack-token SLACK_TOKEN]
                [--slack-channel SLACK_CHANNEL] [-v]
                domain

Infrastructure OSINT

positional arguments:
  domain                domain to search

options:
  -h, --help            show this help message and exit
  -w, --wordlist WORDLIST
                        wordlist with subdomains
  -hw, --hide-wildcards
                        hide wildcard resolutions
  -t, --threads THREADS
                        number of threads [default is 200]
  -nc, --no-collectors  skip passive subdomain enumeration
  -zt, --zone-transfer  attempt to zone transfer from identified name servers
  --permutate           perform permutations on resolved domains
  -pw, --permutation-wordlist PERMUTATION_WORDLIST
                        wordlist to perform permutations with [default is
                        lists/words.txt]
  --reverse             perform reverse dns lookups on resolved public IP
                        addresses
  -ripe, --ripe         query ripe database with the 2nd level domain for
                        networks to be used for reverse lookups
  -r, --ranges RANGES   comma separated ip ranges to perform reverse dns
                        lookups on
  -or, --only-ranges    use only ranges provided with -r or -ripe and not all
                        previously identified IPs
  --portscan            scan resolved public IP addresses for open ports
  -p, --ports PORTS     set of ports to be used by the portscan module
                        [default is medium]
  --takeover            check identified hosts for potential subdomain take-
                        overs
  --tech-profile        perform technology profiling on resolved domains
  --vuln-scan           perform vulnerability scanning on resolved domains
  --interesting         detect interesting subdomains
  --sensitive-scan      scan for sensitive files
  --dir-brute           perform directory and file brute-forcing
  --intelligence        run intelligence module to correlate findings
  --markovify           use markov chains to identify more subdomains
  -ms, --markov-state MARKOV_STATE
                        markov state size [default is 3]
  -ml, --markov-length MARKOV_LENGTH
                        max length of markov substitutions [default is 5]
  -mq, --markov-quantity MARKOV_QUANTITY
                        max quantity of markov results per candidate length
                        [default is 5]
  -f, --flush           purge all records of the specified domain from the
                        database
  --json-report         generate JSON report
  --html-report         generate HTML report
  --diff                show changes compared to previous scan
  --telegram-token TELEGRAM_TOKEN
                        Telegram bot token for notifications
  --telegram-chat TELEGRAM_CHAT_ID
                        Telegram chat ID for notifications
  --slack-token SLACK_TOKEN
                        Slack API token for notifications
  --slack-channel SLACK_CHANNEL
                        Slack channel for notifications
  -v, --version         show program's version number and exit
```

## Full command example
The following, is an example run with all available active arguments:
```
./lepus.py python.org --wordlist lists/subdomains.txt --permutate -pw ~/mypermsword.lst --reverse -ripe -r 10.11.12.0/24 --portscan -p huge --takeover --tech-profile --vuln-scan --interesting --sensitive-scan --dir-brute --markovify -ms 3 -ml 10 -mq 10 --diff --json-report --html-report --telegram-token 123:abc --telegram-chat -123456789
```

The following command flushes all database entries for a specific domain:
```
./lepus.py python.org --flush
```