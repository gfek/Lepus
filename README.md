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
[*]-Retrieving DNS Records...
  \_ A : 23.253.135.79
  \_ AAAA : 2001:4802:7901:0:e60a:1375:0:6
  \_ SOA : ns1.p11.dynect.net
  \_ TXT : "status-page-domain-verification=9y2klhzbxsgk","google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA","google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M","google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o","v=spf1 mx a:psf.upfronthosting.co.za a:mail.wooz.org ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com ~all"
  \_ NS : ns1.p11.dynect.net,ns2.p11.dynect.net,ns3.p11.dynect.net,ns4.p11.dynect.net
  \_ MX : mail.python.org

[*]-Searching Shodan...
  \__ Unique subdomains found: 9
[*]-Searching DNSDumpster...
  \__ Unique subdomains found: 13
[*]-Searching ThreatCrowd...
  \__ Unique subdomains found: 54
[*]-Searching VirusTotal...
  \__  Unique subdomains found: 63
[*]-Searching crt.sh Certificates...
  \__ Unique subdomains found: 32
[*]-Searching FindSubDomain...
  \__ Unique subdomains found: 54
[*]-Searching DNSTrails...
  \__ Unique subdomains found: 21
[*]-Searching Cencys Certificates...
  \__ Unique subdomains found: 15

[*] Retrieving Forward DNS Record (A) for 89 unique subdomains
  \__ packaging.python.org : 151.101.112.223
  \__ es.python.org : 163.172.190.132
  \__ calendario.es.python.org : 176.9.11.11
  \__ www.es.python.org : 163.172.190.132
  \__ empleo.es.python.org : 176.9.11.11
  \__ bugs.python.org : 46.4.197.70
  \__ monitoring.python.org : 140.211.10.83
  \__ blog-es.python.org : 216.58.205.115
  \__ docs.python.org : 151.101.112.223
  \__ python4.org : 192.64.119.58
  \__ lists.es.python.org : 176.9.11.11
  \__ front.python.org : 140.211.10.69
  \__ pl.python.org : 83.143.134.23
  \__ wiki.python.org : 140.211.10.69
  \__ server01.python.org.br : 104.239.163.48
  \__ blog-fr.python.org : 216.58.205.115
  \__ blog-ro.python.org : 216.58.205.115
  \__ status.python.org : 185.166.140.33
  \__ socios.es.python.org : 163.172.190.132
  \__ blog-de.python.org : 216.58.205.115
  \__ jobs.python.org : 23.253.135.79
  \__ hg.es.python.org : 176.9.11.11
  \__ cheeseshop.python.org : 23.253.135.79
  \__ staging.python.org : 23.253.135.79
  \__ mail.python.org : 188.166.95.178
  \__ speed.python.org : 23.253.135.79
  \__ openbadges.es.python.org : 91.121.173.92
  \__ documentos-asociacion.es.python.org : 176.9.11.11
  \__ blog-pt.python.org : 216.58.205.115
  \__ vote.python.org : 23.253.135.79
  \__ forum.pl.python.org : 83.143.134.23
  \__ mail.pl.python.org : 46.175.224.26
  \__ blog-tw.python.org : 216.58.205.115
  \__ www.pl.python.org : 83.143.134.23
  \__ legacy.python.org : 82.94.164.162
  \__ albatross.python.org : 82.94.164.166
  \__ blog-ru.python.org : 216.58.205.115
  \__ python.org : 23.253.135.79
  \__ dinsdale.python.org : 82.94.164.162
  \__ ns1.pl.python.org : 83.143.134.23
  \__ www.python.org : 151.101.112.223
  \__ buildbot.python.org : 140.211.10.71
  \__ svn.python.org : 82.94.164.164
  \__ login.python.org : None
  \__ uk.python.org : 192.30.252.153,192.30.252.154
  \__ packages.python.org : 23.253.135.79
  \__ doc.python.org : 151.101.112.175
  \__ console.python.org : 23.253.135.79
  \__ mx1.python.org : None
  \__ hg.python.org : 104.130.43.97
  \__ staging2.python.org : 23.253.135.79
  \__ blog-ja.python.org : 216.58.205.115
  \__ planet.python.org : 23.253.135.79
  \__ warehouse.python.org : 151.101.112.175
  \__ pypi.python.org : 151.101.112.223
  \__ ximinez.python.org : 82.94.164.163
  \__ infrastucture-staff.python.org : None
  \__ testpypi.python.org : 151.101.112.175
  \__ discuss.python.org : 104.130.43.121
  \__ blog-ko.python.org : 216.58.205.115
  \__ mx.python.org : None
  \__ devguide.python.org : 151.101.112.223
  \__ blog-cn.python.org : 216.58.205.115
  \__ www.bugs.python.org : 151.101.112.223
  \__ blog.python.org : 151.101.112.175
  \__ xml.python.org : None
  \__ ns1.python.org : None
  \__ infrastructure-staff.python.org : None
  \__ e.pypi.python.org : None
  \__ www.openbadges.es.python.org : None
  \__ id.python.org : None
  \__ anthem.python.org : None
  \__ www.status.python.org : None
  \__ africa.python.org : 34.238.97.72,54.227.157.72
  \__ www.hg.es.python.org : None
  \__ ftp.python.org : None
  \__ alliance-python.org : 185.31.40.11
  \__ mxs.python.org : None
  \__ brian.python.org : None
  \__ redesign.python.org : None
  \__ www.lists.es.python.org : None
  \__ g.pypi.python.org : None
  \__ test.python.org : None
  \__ civicrm.python.org : None
  \__ code.python.org : None
  \__ www.alliance-python.org : 185.31.40.11
  \__ www.vote.python.org : None
  \__ pk.python.org : 151.101.112.229
  \__ paste.pound-python.org : 173.255.203.121

[*] Retrieving unique ASNs Networks for unique IPs: 31
  \__ BGP Prefix: 140.211.0.0/16 AS: 3701 AS Name: NERONET - Network for Education and Research in Oregon (NERO), US
  \__ BGP Prefix: 192.30.252.0/24 AS: 36459 AS Name: GITHUB - GitHub, Inc., US
  \__ BGP Prefix: 82.92.0.0/14 AS: 3265 AS Name: XS4ALL-NL Amsterdam, NL
  \__ BGP Prefix: 176.9.0.0/16 AS: 24940 AS Name: HETZNER-AS, DE
  \__ BGP Prefix: 104.239.160.0/19 AS: 27357 AS Name: RACKSPACE - Rackspace Hosting, US
  \__ BGP Prefix: 104.130.0.0/18 AS: 27357 AS Name: RACKSPACE - Rackspace Hosting, US
  \__ BGP Prefix: 91.121.0.0/16 AS: 16276 AS Name: OVH, FR
  \__ BGP Prefix: 173.255.192.0/20 AS: 63949 AS Name: LINODE-AP Linode, LLC, US
  \__ BGP Prefix: 185.166.140.0/24 AS: 133530 AS Name: ATLASSIANPTY-AS-AP ATLASSIAN PTY LTD, AU
  \__ BGP Prefix: 54.226.0.0/15 AS: 14618 AS Name: AMAZON-AES - Amazon.com, Inc., US
  \__ BGP Prefix: 46.175.224.0/20 AS: 43171 AS Name: MAXNET, PL
  \__ BGP Prefix: 151.101.112.0/22 AS: 54113 AS Name: FASTLY - Fastly, US
  \__ BGP Prefix: 163.172.0.0/16 AS: 12876 AS Name: AS12876, FR
  \__ BGP Prefix: 216.58.192.0/19 AS: 15169 AS Name: GOOGLE - Google LLC, US
  \__ BGP Prefix: 34.224.0.0/12 AS: 14618 AS Name: AMAZON-AES - Amazon.com, Inc., US
  \__ BGP Prefix: 185.31.40.0/22 AS: 60362 AS Name: ALWAYSDATA, FR
  \__ BGP Prefix: 23.253.128.0/19 AS: 27357 AS Name: RACKSPACE - Rackspace Hosting, US
  \__ BGP Prefix: 83.143.128.0/21 AS: 35174 AS Name: NFB-AS, PL
  \__ BGP Prefix: 46.4.0.0/16 AS: 24940 AS Name: HETZNER-AS, DE
  \__ BGP Prefix: 188.166.64.0/18 AS: 14061 AS Name: DIGITALOCEAN-ASN - DigitalOcean, LLC, US
  \__ BGP Prefix: 192.64.119.0/24 AS: 22612 AS Name: NAMECHEAP-NET - Namecheap, Inc., US

[*] Retrieving Name & Range from IPWHOIS Information for unique IPs: 31
  \__ LINODE-US : 173.255.192.0 - 173.255.255.255
  \__ OVH : 91.121.160.0 - 91.121.175.255
  \__ RACKS-8-NET-16 : 104.239.128.0 - 104.239.255.255
  \__ EU-DIGITALOCEAN-NL1 : 188.166.0.0 - 188.166.127.255
  \__ NCNET-3 : 192.64.112.0 - 192.64.119.255
  \__ NERONET : 140.211.0.0 - 140.211.255.255
  \__ ONLINE_NET_DEDICATED_SERVERS : 163.172.0.0 - 163.172.255.255
  \__ HOS-192907 : 46.4.197.64 - 46.4.197.71
  \__ AT-88-Z : 34.192.0.0 - 34.255.255.255
  \__ FR-ALWAYSDATA-20130719 : 185.31.40.0 - 185.31.43.255
  \__ NFB-KRAKOW-PL : 83.143.128.0 - 83.143.135.255
  \__ XS4ALL-CUST : 82.94.164.160 - 82.94.164.175
  \__ GOOGLE : 216.58.192.0 - 216.58.223.255
  \__ AMAZON-2011L : 54.224.0.0 - 54.239.255.255
  \__ HETZNER-fsn1-dc5 : 176.9.11.0 - 176.9.11.31
  \__ SKYCA-3 : 151.101.0.0 - 151.101.255.255
  \__ GITHUB-NET4-1 : 192.30.252.0 - 192.30.255.255
  \__ RACKS-8-1393609936777860 : 23.253.134.0 - 23.253.135.255
  \__ NL-ATLASSIAN-20160906 : 185.166.140.0 - 185.166.143.255
  \__ RACKS-8-NET-16 : 104.130.0.0 - 104.130.255.255
  \__ MAXNET : 46.175.224.0 - 46.175.239.255
```

> A file (.txt extension) is created (results) with the name of the given domain