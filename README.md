## Lepus
**Sub-domain finder**

**Lepus** is a utility for identifying and collecting subdomains for a given domain. Subdomain discovery is a crucial part during the reconnaissance phase. It uses four (4) modes:

* Services (Collecting subdomains from the below services)
* Dictionary mode for identifying domains (optional)
* Permutations on discovered subdomains (optional)
* Reverse DNS lookups on identified public IPs (optional)

### Wildcard Identification

The utility checks if the given domain or any generated subdomain is a *wildcard* domain or not.

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
**TO-DO:** Accept list of ASNs as a parameter

### Requirements

|Package|Version|
|---|---|
|tqdm|4.23.4|
|ipwhois|1.0.0|
|requests|2.20.0|
|shodan|1.7.7|
|IPy|0.83|
|beautifulsoup4|4.6.3|
|futures|3.2.0|
|dnspython|1.15.0|
|termcolor|1.1.0|

### Installation

`pip install -r requirements.txt`

### Help

```
usage: lepus.py [-h] [-w WORDLIST] [-t THREADS] [-j] [-nc] [--permutate]
                [-pw PERMUTATION_WORDLIST] [--reverse] [--portscan] [-p PORTS]
                [-v]
                domain

Infrastructure OSINT - find subdomains for a domain

positional arguments:
  domain                domain to search

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        wordlist with subdomains
  -t THREADS, --threads THREADS
                        number of threads [default is 100]
  -j, --json            output to json as well [default is '|' delimited csv]
  -nc, --no-collectors  don't use collectors [default is false]
  --permutate           perform permutations on resolved domains
  -pw PERMUTATION_WORDLIST, --permutation-wordlist PERMUTATION_WORDLIST
                        wordlist to perform permutations with [default is
                        ./lists/words.txt]
  --reverse             perform reverse dns lookups on resolved public IP
                        addresses
  --portscan            scan resolved public IP addresses for open ports
  -p PORTS, --ports PORTS
                        set of ports to be used by the portscan module
                        [default is medium]
  -v, --version         show program's version number and exit
```

### Example

`python lepus.py python.org --wordlist lists/subdomains.txt`

```
         ______  _____           ______  
 |      |______ |_____) |     | (_____   
 |_____ |______ |       |_____| ______)  
                                v2.2.5

[*]-Retrieving DNS Records...
  \__ A : 23.253.135.79
  \__ AAAA : 2001:4802:7901:0:e60a:1375:0:6
  \__ SOA : ns1.p11.dynect.net
  \__ TXT : "google-site-verification=QALZObrGl2OVG8lWUE40uVSMCAka316yADn9ZfCU5OA"
  \__ TXT : "google-site-verification=dqhMiMzpbkSyEhgjGKyEOMlEg2tF0MSHD7UN-MYfD-M"
  \__ TXT : "google-site-verification=w3b8mU3wU6cZ8uSrj3E_5f1frPejJskDpSp_nMWJ99o"
  \__ TXT : "_globalsign-domain-verification=MK_ZKmss4D_DdzGOsssHxxBOK6hJc6LGycFvNOESdZ"
  \__ TXT : "v=spf1 mx a:psf.upfronthosting.co.za a:mail.wooz.org ip4:188.166.95.178/32 ip6:2a03:b0c0:2:d0::71:1 include:stspg-customer.com include:_spf.google.com ~all"
  \__ TXT : "888acb5757da46ad83b7e341ec544c64"
  \__ TXT : "status-page-domain-verification=9y2klhzbxsgk"
  \__ NS : ns3.p11.dynect.net
  \__ NS : ns4.p11.dynect.net
  \__ NS : ns1.p11.dynect.net
  \__ NS : ns2.p11.dynect.net
  \__ MX : mail.python.org

[*]-Searching Censys...
  \__ No Censys API credentials configured
[*]-Searching CertSpotter...
  \__ Unique subdomains found: 23
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
  \__ Unique subdomains found: 59
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
  \__ Unique subdomains found: 42

[*]-Loading Wordlist...
  \__ Unique subdomains loaded: 114441

[*]-Checking for wildcards...
  \__ Progress: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████| 6517/6517 [00:36<00:00, 179.12it/s]
    \__ Wildcards that were identified: 2
      \__ *.front.python.org ==> 140.211.10.69
      \__ *.pl.python.org ==> 83.143.134.23

[*]-Attempting to resolve 114475 hostnames...
  \__ Progress: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████| 114475/114475 [01:38<00:00, 1167.34it/s]
    \__ Hostnames that were resolved: 60
      \__ blog-ko.python.org 216.58.206.51
      \__ es.python.org 163.172.190.132
      \__ hg.es.python.org 176.9.11.11
      \__ mail.python.org 188.166.95.178
      \__ blog-ro.python.org 216.58.206.51
      \__ www.es.python.org 163.172.190.132
      \__ uk.python.org 192.30.252.154
      \__ cheeseshop.python.org 23.253.135.79
      \__ staging.python.org 23.253.135.79
      \__ status.python.org 52.215.192.131
      \__ hg.python.org 104.130.43.97
      \__ pl.python.org 83.143.134.23
      \__ staging2.python.org 23.253.135.79
      \__ www.bugs.python.org 151.101.16.223
      \__ blog-tw.python.org 216.58.206.51
      \__ blog.python.org 151.101.16.175
      \__ blog-ru.python.org 216.58.206.51
      \__ www.pl.python.org 83.143.134.23
      \__ svn.python.org 82.94.164.164
      \__ blog-pt.python.org 216.58.206.51
      \__ front.python.org 140.211.10.69
      \__ blog-ja.python.org 216.58.206.51
      \__ wiki.python.org 140.211.10.69
      \__ python.org 23.253.135.79
      \__ mail.pl.python.org 46.175.224.26
      \__ jobs.python.org 23.253.135.79
      \__ speed.python.org 23.253.135.79
      \__ discuss.python.org 64.71.168.202
      \__ blog-fr.python.org 216.58.206.51
      \__ packaging.python.org 151.101.16.223
      \__ doc.python.org 151.101.16.175
      \__ warehouse-staging.python.org 151.101.16.175
      \__ bugs.python.org 46.4.197.70
      \__ forum.pl.python.org 83.143.134.23
      \__ blog-cn.python.org 216.58.206.51
      \__ devguide.python.org 151.101.16.223
      \__ planet.python.org 23.253.135.79
      \__ legacy.python.org 82.94.164.162
      \__ calendario.es.python.org 176.9.11.11
      \__ ns1.pl.python.org 83.143.134.23
      \__ pypi.python.org 151.101.16.223
      \__ wiki-test.python.org 23.253.135.79
      \__ packages.python.org 23.253.135.79
      \__ warehouse.python.org 151.101.16.175
      \__ openbadges.es.python.org 91.121.173.92
      \__ testpypi.python.org 151.101.16.175
      \__ empleo.es.python.org 176.9.11.11
      \__ blog-de.python.org 216.58.206.51
      \__ console.python.org 23.253.135.79
      \__ dinsdale.python.org 82.94.164.162
      \__ documentos-asociacion.es.python.org 176.9.11.11
      \__ www.python.org 151.101.16.223
      \__ lists.es.python.org 176.9.11.11
      \__ africa.python.org 54.227.157.72
      \__ docs.python.org 151.101.16.223
      \__ blog-es.python.org 216.58.206.51
      \__ buildbot.python.org 140.211.10.71
      \__ monitoring.python.org 140.211.10.83
      \__ socios.es.python.org 163.172.190.132
      \__ pk.python.org 151.101.16.229

[*]-Retrieving unique Autonomous Systems for 22 unique public IPs...
  \__ Progress: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████| 22/22 [00:00<00:00, 69.17it/s]
    \__ ASNs that were identified: 17
      \__ ASN : 16509 BGP Prefix : 52.208.0.0/13 AS Name : AMAZON-02 - Amazon.com, Inc., US
      \__ ASN : 3701 BGP Prefix : 140.211.0.0/16 AS Name : NERONET - Network for Education and Research in Oregon (NERO), US
      \__ ASN : 36459 BGP Prefix : 192.30.252.0/24 AS Name : GITHUB - GitHub, Inc., US
      \__ ASN : 6939 BGP Prefix : 64.71.128.0/18 AS Name : HURRICANE - Hurricane Electric LLC, US
      \__ ASN : 3265 BGP Prefix : 82.92.0.0/14 AS Name : XS4ALL-NL Amsterdam, NL
      \__ ASN : 24940 BGP Prefix : 176.9.0.0/16 AS Name : HETZNER-AS, DE
      \__ ASN : 54113 BGP Prefix : 151.101.16.0/22 AS Name : FASTLY - Fastly, US
      \__ ASN : 27357 BGP Prefix : 104.130.0.0/18 AS Name : RACKSPACE - Rackspace Hosting, US
      \__ ASN : 14618 BGP Prefix : 54.226.0.0/15 AS Name : AMAZON-AES - Amazon.com, Inc., US
      \__ ASN : 43171 BGP Prefix : 46.175.224.0/20 AS Name : MAXNET, PL
      \__ ASN : 12876 BGP Prefix : 163.172.0.0/16 AS Name : AS12876, FR
      \__ ASN : 16276 BGP Prefix : 91.121.0.0/16 AS Name : OVH, FR
      \__ ASN : 24940 BGP Prefix : 46.4.0.0/16 AS Name : HETZNER-AS, DE
      \__ ASN : 35174 BGP Prefix : 83.143.128.0/21 AS Name : NFB-AS, PL
      \__ ASN : 27357 BGP Prefix : 23.253.128.0/19 AS Name : RACKSPACE - Rackspace Hosting, US
      \__ ASN : 14061 BGP Prefix : 188.166.64.0/18 AS Name : DIGITALOCEAN-ASN - DigitalOcean, LLC, US
      \__ ASN : 15169 BGP Prefix : 216.58.206.0/23 AS Name : GOOGLE - Google LLC, US

[*]-Retrieving unique WHOIS records for 22 unique public IPs...
  \__ Progress: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████| 22/22 [00:03<00:00,  5.81it/s]
    \__ WHOIS records that were identified: 17
      \__ 104.130.0.0 - 104.130.255.255 : RACKS-8-NET-16
      \__ 52.208.0.0 - 52.215.255.255 : AMAZON-DUB
      \__ 46.175.224.0 - 46.175.239.255 : MAXNET
      \__ 46.4.197.64 - 46.4.197.71 : HOS-192907
      \__ 216.58.192.0 - 216.58.223.255 : GOOGLE
      \__ 140.211.0.0 - 140.211.255.255 : NERONET
      \__ 151.101.0.0 - 151.101.255.255 : SKYCA-3
      \__ 176.9.11.0 - 176.9.11.31 : HETZNER-fsn1-dc5
      \__ 163.172.0.0 - 163.172.255.255 : ONLINE_NET_DEDICATED_SERVERS
      \__ 91.121.160.0 - 91.121.175.255 : OVH
      \__ 82.94.164.160 - 82.94.164.175 : XS4ALL-CUST
      \__ 188.166.0.0 - 188.166.127.255 : EU-DIGITALOCEAN-NL1
      \__ 83.143.128.0 - 83.143.135.255 : NFB-KRAKOW-PL
      \__ 192.30.252.0 - 192.30.255.255 : GITHUB-NET4-1
      \__ 23.253.134.0 - 23.253.135.255 : RACKS-8-1393609936777860
      \__ 54.224.0.0 - 54.239.255.255 : AMAZON-2011L
      \__ 64.71.128.0 - 64.71.191.255 : HURRICANE-2

```
