## Lepus
**Sub-domain finder**

**Lepus** is a utility where it can help pentesters to identify and collect sub-domains for a given domain. Subdomain discovery is a crucial part during the reconnaissance phase. 

### Services

The utility is collecting data from the following services:

* [Shodan](https://www.shodan.io/) 
* [VirusTotal](https://www.virustotal.com/)
* [DNSDumpster](https://dnsdumpster.com/)
* [ThreatCrowd](https://www.threatcrowd.org/)
* [Censys](https://censys.io/)
* [Crt.sh](https://crt.sh/)
* [Findsubdomains](https://findsubdomains.com/)
* [DNSTrails](https://securitytrails.com/dns-trails)

|Service|API is required|
|---|:---:|
|Shodan|Yes|
|VirusTotal|Yes|
|DNSDumpster|No|
|ThreatCrowd|No|
|Censys|Yes|
|Crt.sh|No|
|Findsubdomains|No|
|DNSTrails|Yes|

In a case that you want to consume services that support API keys then you have to place your API keys in the file `config.ini`.

```
[Cencys]
UID=<YourUID>
SECRET=<YourSecret>

[Shodan]
SHODAN_API_KEY=<YourShodanAPI>

[VirusTotal]
VT_API_KEY=<YourVTAPI>

[DNSTrail]
DNSTrail_API_KEY=<YourDNATrailAPI>
```

### Requirements

|Package|Version|
|---|---|
|beautifulsoup4| 4.6.0
|bs4|            0.0.1
|certifi|        2018.4.16
|chardet|        3.0.4
|click|          6.7
|click-plugins|  1.0.3
|colorama|       0.3.9
|dnspython|      1.15.0
|futures|        3.2.0
|idna|           2.6
|ipaddr|         2.2.0
|ipwhois|        1.0.0
|pip|            10.0.0
|requests|       2.18.4
|setuptools|     39.0.1
|shodan|         1.7.7
|termcolor|      1.1.0
|urllib3|        1.22
|wheel|          0.31.0
|XlsxWriter|     1.0.4

### Help

```
usage: lepus.py [-h] -s SEARCH [-v]

OSINT Infrastructure-find subdomains for a given domain

optional arguments:
  -h, --help  show this help message and exit
  -s SEARCH   domain is required
  -v          show program's version number and exit
```

### Example

`python subdomainator.py -s python.org`

![subdomainator](/Users/neuro/Desktop/Screen Shot 2018-04-18 at 4.25.47 PM.png)

> A file (.txt extension) is created (results) with the name of the given domain