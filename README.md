## Lepus
**Sub-domain finder**

**Lepus** is a utility for identifying and collecting subdomains for a given domain. Subdomain discovery is a crucial part during the reconnaissance phase. 

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

`python lepus.py -s python.org`

```
[*]-Checking Shodan...
  \__ Unique subdomains found: 8
[*]-Checking DNSDumpster...
  \__ Unique subdomains found: 13
[*]-Checking ThreatCrowd...
  \__ Unique subdomains found: 54
[*]-Checking VirusTotal...
  \__ Unique subdomains found: 62
[*]-Checking crt.sh Certificates...
  \__ Unique subdomains found: 32
[*]-Checking FindSubDomain...
  \__ Unique subdomains found: 54
[*]-Checking DNSTrails...
  \__ Unique subdomains found: 21
[*]-Checking Cencys Certificates...
  \__ Unique subdomains found: 15

[*] Checking DNS Record [A] for 88 unique subdomains
  \__ mail.python.org : 188.166.95.178
  \__ bugs.python.org : 46.4.197.70
  \__ forum.pl.python.org : 83.143.134.23
  \__ www.bugs.python.org : 151.101.112.223
  \__ wiki.python.org : 140.211.10.69
  \__ e.pypi.python.org : None
  \__ front.python.org : 140.211.10.69
  \__ python.org : 23.253.135.79
  \__ mx1.python.org : None
  \__ www.lists.es.python.org : None
  \__ www.status.python.org : None
  \__ www.hg.es.python.org : None
  \__ monitoring.python.org : 140.211.10.83
  \__ packaging.python.org : 151.101.112.223
  \__ openbadges.es.python.org : 91.121.173.92
  \__ empleo.es.python.org : 176.9.11.11
  \__ docs.python.org : 151.101.112.223
  \__ g.pypi.python.org : None
  \__ calendario.es.python.org : 176.9.11.11
  \__ www.es.python.org : 163.172.190.132
  \__ login.python.org : None
  \__ www.pl.python.org : 83.143.134.23
  \__ pl.python.org : 83.143.134.23
  \__ hg.es.python.org : 176.9.11.11
  \__ mx.python.org : None
  \__ lists.es.python.org : 176.9.11.11
  \__ mail.pl.python.org : 46.175.224.26
  \__ devguide.python.org : 151.101.112.223
  \__ pypi.python.org : 151.101.112.223
  \__ xml.python.org : None
  \__ ns1.python.org : None
  \__ albatross.python.org : 82.94.164.166
  \__ anthem.python.org : None
  \__ socios.es.python.org : 163.172.190.132
  \__ documentos-asociacion.es.python.org : 176.9.11.11
  \__ infrastucture-staff.python.org : None
  \__ infrastructure-staff.python.org : None
  \__ ns1.pl.python.org : 83.143.134.23
  \__ legacy.python.org : 82.94.164.162
  \__ dinsdale.python.org : 82.94.164.162
  \__ www.python.org : 151.101.112.223
  \__ es.python.org : 163.172.190.132
  \__ www.vote.python.org : None
  \__ redesign.python.org : None
  \__ uk.python.org : 192.30.252.153,192.30.252.154
  \__ mxs.python.org : None
  \__ svn.python.org : 82.94.164.164
  \__ ftp.python.org : None
  \__ brian.python.org : None
  \__ test.python.org : None
  \__ discuss.python.org : 104.130.43.121
  \__ ximinez.python.org : 82.94.164.163
  \__ civicrm.python.org : None
  \__ code.python.org : None
  \__ id.python.org : None
  \__ www.openbadges.es.python.org : None
  \__ blog-ro.python.org : 216.58.212.19
  \__ blog-ko.python.org : 216.58.212.19
  \__ blog-pt.python.org : 216.58.212.19
  \__ blog-de.python.org : 216.58.212.19
  \__ blog-fr.python.org : 216.58.212.19
  \__ warehouse.python.org : 151.101.112.175
  \__ blog-ru.python.org : 216.58.212.19
  \__ blog.python.org : 151.101.112.175
  \__ blog-ja.python.org : 216.58.212.19
  \__ doc.python.org : 151.101.112.175
  \__ blog-cn.python.org : 216.58.212.19
  \__ testpypi.python.org : 151.101.112.175
  \__ blog-es.python.org : 216.58.212.19
  \__ blog-tw.python.org : 216.58.212.19
  \__ cheeseshop.python.org : 23.253.135.79
  \__ planet.python.org : 23.253.135.79
  \__ vote.python.org : 23.253.135.79
  \__ speed.python.org : 23.253.135.79
  \__ staging2.python.org : 23.253.135.79
  \__ packages.python.org : 23.253.135.79
  \__ jobs.python.org : 23.253.135.79
  \__ console.python.org : 23.253.135.79
  \__ staging.python.org : 23.253.135.79
  \__ hg.python.org : 104.130.43.97
  \__ status.python.org : 185.166.140.32
  \__ pk.python.org : 151.101.112.229
  \__ paste.pound-python.org : None
  \__ server01.python.org.br : None
  \__ buildbot.python.org : None
  \__ africa.python.org : None
  \__ www.alliance-python.org : None
  \__ alliance-python.org : None

[*] Unique ASNs Networks for unique IPs: 24
  \__ CIDR: 140.211.0.0/16 ASN: 3701 Descriprion: NERONET - Network for Education and Research in Oregon (NERO), US
  \__ CIDR: 192.30.252.0/24 ASN: 36459 Descriprion: GITHUB - GitHub, Inc., US
  \__ CIDR: 82.92.0.0/14 ASN: 3265 Descriprion: XS4ALL-NL Amsterdam, NL
  \__ CIDR: 176.9.0.0/16 ASN: 24940 Descriprion: HETZNER-AS, DE
  \__ CIDR: 151.101.112.0/22 ASN: 54113 Descriprion: FASTLY - Fastly, US
  \__ CIDR: 104.130.0.0/18 ASN: 27357 Descriprion: RACKSPACE - Rackspace Hosting, US
  \__ CIDR: 185.166.140.0/24 ASN: 133530 Descriprion: ATLASSIANPTY-AS-AP ATLASSIAN PTY LTD, AU
  \__ CIDR: 216.58.212.0/24 ASN: 15169 Descriprion: GOOGLE - Google LLC, US
  \__ CIDR: 46.175.224.0/20 ASN: 43171 Descriprion: MAXNET, PL
  \__ CIDR: 91.121.0.0/16 ASN: 16276 Descriprion: OVH, FR
  \__ CIDR: 163.172.0.0/16 ASN: 12876 Descriprion: AS12876, FR
  \__ CIDR: 46.4.0.0/16 ASN: 24940 Descriprion: HETZNER-AS, DE
  \__ CIDR: 83.143.128.0/21 ASN: 35174 Descriprion: NFB-AS, PL
  \__ CIDR: 23.253.128.0/19 ASN: 27357 Descriprion: RACKSPACE - Rackspace Hosting, US
  \__ CIDR: 188.166.64.0/18 ASN: 14061 Descriprion: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
```

> A file (.txt extension) is created (results) with the name of the given domain