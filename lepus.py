# -*- coding: utf-8 -*-
import shodan
import argparse
import sys
import json
from DNSDumpsterAPI import DNSDumpsterAPI
import warnings
import concurrent.futures
import dns.resolver
import requests
from bs4 import BeautifulSoup
from colorama import init
from termcolor import colored
from ConfigParser import SafeConfigParser
import time
import tqdm
import os

init()
warnings.filterwarnings("ignore")

def DNS_Records(domain):

	print colored("\n[*]-Retrieving DNS Records...",'yellow')

	RES={}
	MX=[]
	NS=[]
	A=[]
	AAAA=[]
	SOA=[]
	CNAME=[]
	TXT=[]
	
	resolver = dns.resolver.Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1

	rrtypes=['A','MX','NS','AAAA','SOA','TXT']
	for r in rrtypes:
		try:
			Aanswer=resolver.query(domain,r)
			for answer in Aanswer:
				if r=='A':
					A.append(answer.address)
					RES.update({r:A})
				if r=='MX':
					MX.append(answer.exchange.to_text()[:-1])
					RES.update({r:MX})
				if r=='NS':
					NS.append(answer.target.to_text()[:-1])
					RES.update({r:NS})
				if r=='AAAA':
					AAAA.append(answer.address)
					RES.update({r:AAAA})
				if r=='SOA':
					SOA.append(answer.mname.to_text()[:-1])
					RES.update({r:SOA})
				if r=='TXT':
					TXT.append(str(answer))
					RES.update({r:TXT})
		except dns.resolver.NXDOMAIN:
			pass
		except dns.resolver.NoAnswer:
			pass
		except dns.name.EmptyLabel:
			pass
		except dns.resolver.NoNameservers:
			pass
		except dns.resolver.Timeout:
			pass
		except dns.exception.DNSException:
			pass
	return RES

def get_A_Record(host):

	A=[]
	
	resolver = dns.resolver.Resolver()
	resolver.timeout = 5
	resolver.lifetime = 5

	try:
		Aanswer=resolver.query(host,'A')
		for answer in Aanswer:
			A.append(answer.address)
	except dns.resolver.NXDOMAIN:
		A.append("None")
		pass
	except dns.resolver.NoAnswer:
		A.append("None")
		pass
	except dns.name.EmptyLabel:
		A.append("None")
		pass
	except dns.resolver.NoNameservers:
		A.append("None")
		pass
	except dns.resolver.Timeout:
		A.append("None")
		pass
	except dns.exception.DNSException:
		A.append("None")
		pass
	return A

def check_wildcard_domain(domain):
	print colored("[*]-Checking if domain {}".format(args.search) + " is wildcard...",'yellow')
	
	fres=[]
	epoch_time = str(int(time.time()))
	res=get_A_Record(epoch_time+"."+domain)
	fres.append(epoch_time+"."+domain+":"+''.join(res))
	return fres

def subShodan(domain):
	hosts=[]
	parser = SafeConfigParser()
	parser.read('config.ini')
		
	SHODAN_API_KEY=parser.get('Shodan','SHODAN_API_KEY')
	api=shodan.Shodan(SHODAN_API_KEY)
	
	print colored("\n[*]-Searching Shodan...",'yellow')

	results=api.search('hostname:.{}'.format(domain))
	try:
		for res in results['matches']:
			hosts.append(''.join(res['hostnames']))
	except KeyError:
		pass

	print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(hosts)),'yellow')
	return hosts

def subVT(domain):
	VT=[]
	
	print colored("[*]-Searching VirusTotal...",'yellow')

	parser = SafeConfigParser()
	parser.read('config.ini')
	parameters = {'domain': domain, 'apikey': parser.get('VirusTotal','VT_API_KEY')}
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'}
	try:
		response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=parameters,headers=headers)
		response_dict = response.json()
		if 'subdomains' in response_dict:
			for sd in response_dict['subdomains']:
				VT.append(sd)
		print "  \__ ", colored("Unique subdomains found:",'cyan'), colored(len(set(VT)),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return VT

def subDnsDumpster(domain):
	print colored("[*]-Searching DNSDumpster...",'yellow')
	try:
		dnsdumpsubdomains = DNSDumpsterAPI({'verbose': False}).search(domain)
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(dnsdumpsubdomains)),'yellow')
		return dnsdumpsubdomains
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass

def subThreatCrowd(domain):
	TC=[]
	
	print colored("[*]-Searching ThreatCrowd...",'yellow')

	try:
		result =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params = {"domain":domain})
		try:
			RES = json.loads(result.text)
			resp_code = int(RES['response_code'])
			if resp_code==1:
				for sd in RES['subdomains']:
					TC.append(sd)
			print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(TC)),'yellow')
		except ValueError:
			pass
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return TC

def subCencys(domain):
	C=[]

	print colored("[*]-Searching Cencys Certificates...",'yellow')
	
	parser = SafeConfigParser()
	parser.read('config.ini')


	API_URL = "https://www.censys.io/api/v1"
	UID = parser.get('Cencys','UID')
	SECRET = parser.get('Cencys','SECRET')

	payload = {'query': domain}
	try:
		res = requests.post(API_URL + "/search/certificates", json=payload, auth=(UID, SECRET))
		payload=res.json()['results']
		for r in payload:
			str = r["parsed.subject_dn"]
			str1=str.split("CN=")[1]
			str1=str1.split(",")
			if domain in str1[0] and not ''.join(str1[0]).startswith('*'):
				C.append(''.join(str1[0]))
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(C)),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return C

def subCrt(domain):
	CRT=[]
	print colored("[*]-Searching crt.sh Certificates...",'yellow')
	
	parameters = {'q': '%.{}'.format(domain), 'output':'json'}
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0','content-type': 'application/json'}
	try:
		response = requests.get("https://crt.sh/?",params=parameters, headers=headers)
		if response.status_code==200:
			content=response.content.decode('utf-8')
			data = json.loads("[{}]".format(content.replace('}{', '},{')))
			for d in data:
				if not ''.join(d['name_value']).startswith('*'):
					CRT.append(d['name_value'])
		elif response.status_code==404:
			print colored("\tA 404 error was issued by the remote server!!! (Potentially too many json results)",'yellow')
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(CRT)),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return CRT

def subFindSubDomains(domain):
	FSD=[]

	print colored("[*]-Searching FindSubDomain...",'yellow')

	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'}
	url = "https://findsubdomains.com/subdomains-of/{}".format(domain)
	try:
		response = requests.get(url,headers=headers,verify=False)
		name_soup = BeautifulSoup(response.text,"html.parser")
		for link in name_soup.findAll("a",{"class":"aggregated-link"}):
			try:
				if link.string is not None:
					FSD.append(link.string.strip())
			except KeyError:
				pass
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(FSD)),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return FSD

def subdnstrails(domain):
	DT=[]

	print colored("[*]-Searching DNSTrails...",'yellow')

	parser = SafeConfigParser()
	parser.read('config.ini')
	
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'\
	,'content-type': 'application/json'\
	,'APIKEY':parser.get('DNSTrail','DNSTrail_API_KEY')}

	url='https://api.securitytrails.com/v1/domain/{}/subdomains'.format(domain)
	try:
		response = requests.get(url, headers=headers)
		payload=response.json()
		for k,v in payload.items():
			if v:
				for dnsvalue in v:
					DT.append(dnsvalue)
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(set(DT)),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return DT

def dnsdb(domain):
	dnsdb=[]
	print colored("[*]-Searching DNSDB.COM...",'yellow')
	
	headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0'}
	url = "http://www.dnsdb.org/{}/".format(domain)
	try:
		response = requests.get(url,headers=headers)
		name_soup = BeautifulSoup(response.text,"html.parser")
		for link in name_soup.findAll("a"):
			try:
				if link.string is not None:
					dnsdb.append(link.string)
			except KeyError:
				pass
		print "  \__", colored("Unique subdomains found:",'cyan'), colored(len(dnsdb),'yellow')
	except requests.exceptions.RequestException as err:
		print "  \__", colored(err,'red')
		pass
	except requests.exceptions.HTTPError as errh:
		print "  \__", colored(errh,'red')
		pass
	except requests.exceptions.ConnectionError as errc:
		print "  \__", colored(errc,'red')
		pass
	except requests.exceptions.Timeout as errt:
		print "  \__", colored(errt,'red')
		pass
	return dnsdb

def IP2CIDR(ip):
	from ipwhois.net import Net
	from ipwhois.asn import IPASN

	net = Net(ip)
	obj = IPASN(net)
	results = obj.lookup()
	return results

def IP2WHois(ip):
	from ipwhois import IPWhois
	obj = IPWhois(ip)
	results = obj.lookup_whois()
	return results['nets']

def readfile(file):
	file=open(file,'r')
	hosts=[host for host in file.read().split('\n')]
	file.close()
	return hosts

def createdir(domain):
	if not os.path.exists(domain):
		os.makedirs(domain)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog="subdomainator.py",description='OSINT Infrastructure-find subdomains for a domain')
	parser.add_argument("-s", action="store", dest='search',help="domain is required",required=True)
	parser.add_argument("-w", action="store", dest='wordlist',help="wordlist with subdomains [required]")
	parser.add_argument("-t", action="store", dest='threads',help="specify # of threads [default is 100]", default=100)
	parser.add_argument("-v", action="version",version="%(prog)s v1.0")
	args = parser.parse_args()

	if args.search is None:
	    parser.parse_args(['-h'])

	createdir(args.search)

	for res in check_wildcard_domain(args.search):
		wildcardip=res.split(':')[1]
		if 'None' not in res:
			print "  \__", colored("Wildcard domain was identified",'red')
		else:
			print "  \__", "Not a wildcard domain."

	getDNS=DNS_Records(args.search)
	for k,v in getDNS.iteritems():
		print "  \_", colored(k,'cyan'),":",colored(','.join(v), 'yellow')

	try:
		shodan_list=subShodan(args.search)
	except shodan.exception.APIError:
		shodan_list=[]
		pass
	
	try:
		dnsdumpster_list=[unicode(domain+'.'+args.search) for domain in subDnsDumpster(args.search)]
	except:
		dnsdumpster_list=[]
		pass
	
	try:
		threatcrowd_list=subThreatCrowd(args.search)
	except:
		threatcrowd_list=[]
		pass
	
	try:
		virustotal_list=subVT(args.search)
	except:
		virustotal_list=[]
		pass
	
	try:
		crtsh_list=subCrt(args.search)
	except:
		crtsh_list=[]
		pass

	try:
		fundsubdomains_list=subFindSubDomains(args.search)
	except:
		fundsubdomains_list=[]
		pass
	
	try:
		dnstrails_list=[domain+'.'+args.search for domain in subdnstrails(args.search)]
	except:
		dnstrails_list=[]
		pass

	try:
		cencys_list=subCencys(args.search)
	except:
		cencys_list=[]
		pass
	
	try:
		dnsdb_list=dnsdb(args.search)
	except:
		dnsdb_list=[]
		pass

	subdomains_list=shodan_list+ \
				dnsdumpster_list+ \
				threatcrowd_list+ \
				virustotal_list+ \
				crtsh_list+\
				fundsubdomains_list+\
				dnsdb_list+\
				cencys_list+\
				dnstrails_list
	
	IPs=[]
	resForDNS=[]
	
	if args.wordlist:
		print colored("\n[*] Starting dictionary attack mode [Forward DNS is performed]...",'yellow')
		with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
			future_to_a={executor.submit(get_A_Record, host+"."+args.search):host for host in readfile(args.wordlist)}
			done_iter = concurrent.futures.as_completed(future_to_a)
			done_iter = tqdm.tqdm(done_iter, total=len(readfile(args.wordlist)), desc=colored(args.wordlist,'cyan'), dynamic_ncols=True)

			for future in done_iter:
				r=future_to_a[future]
				try:
					a=future.result()
					if 'None' not in a:
						if wildcardip!=''.join(a):
							resForDNS.append(r.lower()+"."+args.search+":"+','.join(a))
					for ips in a:
						IPs.append(ips)
				except Exception as exc:
					print "  \__", ('%r generated an exception: %s' % (r, exc))
		
		print "  \_", colored("Number of subdomains found:",'yellow'),"{}".format(colored(str(len(resForDNS)),'red'))
		for bfres in resForDNS:
			print "    \__", colored(bfres.split(':')[0],'cyan'), \
			colored(bfres.split(':')[1],'yellow')

	print colored("\n[*] Retrieving Forward DNS Record (A) for",'yellow'), "{}".format(colored(len(set(subdomains_list)),'red'))\
	, colored("unique subdomains",'yellow')

	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
			future_to_domain={executor.submit(get_A_Record, domain):domain for domain in set(subdomains_list)}
			for future in concurrent.futures.as_completed(future_to_domain):
				dom=future_to_domain[future]
				try:
					DNSAdata = future.result()
					resForDNS.append(dom.lower()+":"+','.join(DNSAdata))
					for ips in DNSAdata:
						IPs.append(ips)
				except Exception as exc:
					print "  \__", colored('%r generated an exception: %s' % (dom, exc),'red')
	except ValueError:
		pass

	FinalDNSLista=[]

	for cleanLista in set(resForDNS):
		FinalDNSLista.append(cleanLista)

	fh = open(args.search+'/subdomains.txt', "w+")
	FinalDNSLista.sort(key = lambda x: x.split(':')[1])
	for res in FinalDNSLista:
		print "  \__", colored(res.split(':')[0],'cyan'), \
		colored(res.split(':')[1],'yellow')
		fh.writelines(str(res.split(':')[0].encode('utf-8').strip())+','+str(res.split(':')[1])+'\n')
	fh.close()

	print colored("\n[*] Retrieving unique ASNs Networks for unique IPs:",'yellow'), "{}".format(colored(len(set(IPs)),'red'))

	IP2ASN={}

	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
			future_to_ip2asn={executor.submit(IP2CIDR, ip):ip for ip in set(IPs) if "None" not in ip}
			for future in concurrent.futures.as_completed(future_to_ip2asn):
				ip=future_to_ip2asn[future]
				try:
					IP2ASNDATA = future.result()
					IP2ASN.update({ip:IP2ASNDATA})
				except Exception as exc:
					print "  \__", colored('%r generated an exception: %s' % (ip, exc),'red')
	except ValueError:
		pass

	values_from_IP2ASN=[]
	for k,v in IP2ASN.items():
		if v not in values_from_IP2ASN:
			values_from_IP2ASN.append(v)
	
	fh = open(args.search+'/IP2ASN.txt', "w+")
	for value in values_from_IP2ASN:
		print "  \__", colored("BGP Prefix:",'cyan'),colored(value['asn_cidr'],'yellow'),\
			colored("AS:",'cyan'),colored(value['asn'],'yellow'),\
			colored("AS Name:",'cyan'),colored(value['asn_description'],'yellow')
		fh.writelines(str(value['asn_cidr'])+','+str(value['asn'])+','+str(value['asn_description'])+'\n')
	fh.close()

	print colored("\n[*] Retrieving Name & Range from IPWHOIS Information for unique IPs:",'yellow'), "{}".format(colored(len(set(IPs)),'red'))

	IP2WHOIS=[]
	
	try:
		with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
			future_to_ipwhois={executor.submit(IP2WHois, ip):ip for ip in set(IPs) if "None" not in ip}
			for future in concurrent.futures.as_completed(future_to_ipwhois):
				ip=future_to_ipwhois[future]
				try:
					IPWHOIS = future.result()
					IP2WHOIS.append((IPWHOIS[0])['name']+':'+(IPWHOIS[0])['range'])
					
				except Exception as exc:
					print "  \__", colored('%r generated an exception: %s' % (ip, exc),'red')
	except ValueError:
		pass

	fh = open(args.search+'/IP2WHOIS.txt', "w+")
	for res in set(IP2WHOIS):
		split_for_color=res.split(':')
		print "  \__",colored(split_for_color[0],'cyan'),\
		':',colored(split_for_color[1],'yellow')
		fh.writelines(str(split_for_color[0])+','+str(split_for_color[1])+'\n')
	fh.close()