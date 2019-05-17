import re
import sys
from os.path import join
from tqdm import tqdm
from json import dumps
from requests import get
from termcolor import colored
from dns.name import EmptyLabel
from warnings import simplefilter
from dns.exception import DNSException
from concurrent.futures import ThreadPoolExecutor, as_completed
from dns.resolver import Resolver, NXDOMAIN, NoAnswer, NoNameservers, Timeout
import utilities.MiscHelpers

simplefilter("ignore")

headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0", "Content-Type": "application/json"}
signatures = {
	"Amazon AWS/S3": "NoSuchBucket",
	"Bitbucket": "Repository not found",
	"Campaign Monitor": "Double check the URL or <a href=\"mailto:help@createsend.com",
	"Cargo Collective": "<title>404 &mdash; File not found</title>",
	"Feedpress": "The feed has not been found.",
	"Ghost.io": "The thing you were looking for is no longer here, or never was",
	"Github": "There isn't a GitHub Pages site here.",
	"Helpjuice": "There's nothing here, yet.",
	"Helpjuice 2": "We could not find what you're looking for.",
	"Helpscout": "No settings were found for this company",
	"Heroku": "<title>No such app</title>",
	"JetBrains": "is not a registered InCloud YouTrack",
	"Readme.io": "Project doesnt exist... yet!",
	"Surge.sh": "project not found",
	"Tumblr": "Whatever you were looking for doesn't currently exist at this address.",
	"Tilda": "Domain has been assigned.",
	"Tilda 2": "Please renew your subscription",
	"UserVoice": "Perhaps you meant to visit",
	"UserVoice 2": "This UserVoice subdomain is currently available!",
	"Wordpress": "Do you want to register",
	"Strikingly": "But if you're looking to build your own website",
	"Uptime Robot": "page not found",
	"Pantheon": "The gods are wise",
	"Teamwork": "Oops - We didn't find your site.",
	"Intercom": "This page is reserved for artistic dogs",
	"Webflow": "The page you are looking for doesn't exist or has been moved",
	"Wishpond": "https://www.wishpond.com/404?campaign=true",
	"Aftership": "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
	"Aha!": "There is no portal here ... sending you back to Aha!",
	"Brightcove": "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",
	"Bigcartel": "<h1>Oops! We couldn&#8217;t find that page.</h1>",
	"Acquia": "Sorry, we could not find any content for this web address",
	"Simplebooklet": ">Sorry, we can't find this <a",
	"Getresponse": "With GetResponse Landing Pages, lead generation has never been easier",
	"Vend": "Looks like you've traveled too far into cyberspace",
	"Tictail": "to target URL: <a href=\"https://tictail.com"
}


def findSignatures(domainToTry, signature, neededMatches):
	numberOfMatches = 0

	try:
		if signature in str(get("http://" + domainToTry, headers=headers, verify=False).content, "utf-8"):
			numberOfMatches += 1

			if neededMatches <= numberOfMatches:
				return True

	except Exception:
		pass

	try:
		if signature in str(get("https://" + domainToTry, headers=headers, verify=False).content, "utf-8"):
			numberOfMatches += 1

			if neededMatches <= numberOfMatches:
				return True

	except Exception:
		pass

	return False


def findNX(domainToTry):
	resolver = Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1

	try:
		resolver.query(domainToTry)

	except NXDOMAIN:
		return True

	except Exception:
		pass

	return False


def amazonS3(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Amazon AWS/S3"], 2):
		outcome = ["Amazon AWS/S3 Takeover", domain, CNAME]

	return outcome


def bitbucket(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(CNAME, signatures["Bitbucket"], 1):
		outcome = ["Bitbucket Takeover", domain, CNAME]

	return outcome


def campaignMonitor(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(CNAME, signatures["Campaign Monitor"], 1):
		outcome = ["Campaign Monitor Takeover", domain, CNAME]

	return outcome


def cargoCollective(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(CNAME, signatures["Cargo Collective"], 1):
		outcome = ["Cargo Collective Takeover", domain, CNAME]

	return outcome


def cloudfront(domain, ARecords, CNAME):
	outcome = []
	# implement me - odd case
	return outcome


def fastly(domain, ARecords, CNAME):
	outcome = []
	# implement me - odd case
	return outcome


def feedpress(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Feedpress"], 2):
		outcome = ["Feedpress Takeover", domain, CNAME]

	return outcome


def ghost(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Ghost.io"], 1):
		outcome = ["Ghost.io Takeover", domain, CNAME]

	return outcome


def github(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Github"], 1):
		outcome = ["Github Takeover", domain, CNAME]

	return outcome


def helpjuice(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(CNAME, signatures["Helpjuice"], 1) or findSignatures(CNAME, signatures["Helpjuice 2"], 1):
		outcome = ["Helpjuice Takeover", domain, CNAME]

	return outcome


def helpscout(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Helpscout"], 1):
		outcome = ["Helpscout Takeover", domain, CNAME]

	return outcome


def heroku(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(CNAME, signatures["Heroku"], 2):
		outcome = ["Heroku Takeover", domain, CNAME]

	return outcome


def jetbrains(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["JetBrains"], 1):
		outcome = ["JetBrains Takeover", domain, CNAME]

	return outcome


def azure(domain, ARecords, CNAME):
	outcome = []

	if findNX(CNAME):
		outcome = ["Azure Takeover", domain, CNAME]

	return outcome


def netlify(domain, ARecords, CNAME):
	outcome = []
	# implement me - odd case
	return outcome


def readme(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Readme.io"], 1):
		outcome = ["Readme.io Takeover", domain, CNAME]

	return outcome


def shopify(domain, ARecords, CNAME):
	outcome = []
	# implement me - odd case
	return outcome


def surge(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Surge.sh"], 1):
		outcome = ["Surge.sh Takeover", domain, CNAME]

	return outcome


def tumblr(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Tumblr"], 1):
		outcome = ["Tumblr Takeover", domain, CNAME]

	return outcome


def tilda(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Tilda"], 1) or findSignatures(domain, signatures["Tilda 2"], 1):
		outcome = ["Tilda Takeover", domain, CNAME]

	return outcome


def uservoice(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["UserVoice"], 1) or findSignatures(domain, signatures["UserVoice 2"], 1):
		outcome = ["UserVoice Takeover", domain, CNAME]

	return outcome


def wordpress(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Wordpress"], 1):
		outcome = ["Wordpress Takeover", domain, CNAME]

	return outcome


def smugmug(domain, ARecords, CNAME):
	outcome = []

	try:
		if get("http://" + domain, headers=headers, verify=False).status_code == 404:
			outcome = ["Smugmug Takeover", domain, CNAME]
			return outcome

	except Exception:
		pass

	try:
		if get("https://" + domain, headers=headers, verify=False).status_code == 404:
			outcome = ["Smugmug Takeover", domain, CNAME]
			return outcome

	except Exception:
		pass

	resolver = Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1

	try:
		resolver.query(CNAME)

	except NXDOMAIN:
		outcome = ["Smugmug Takeover", domain, CNAME]

	return outcome


def strikingly(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Strikingly"], 1):
		outcome = ["Strikingly Takeover", domain, CNAME]

	return outcome


def uptimerobot(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Uptime Robot"], 1):
		outcome = ["Uptime Robot Takeover", domain, CNAME]

	return outcome


def pantheon(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Pantheon"], 1):
		outcome = ["Pantheon Takeover", domain, CNAME]

	return outcome


def teamwork(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Teamwork"], 1):
		outcome = ["Teamwork Takeover", domain, CNAME]

	return outcome


def intercom(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Intercom"], 1):
		outcome = ["Intercom Takeover", domain, CNAME]

	return outcome


def webflow(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Webflow"], 1):
		outcome = ["Webflow Takeover", domain, CNAME]

	return outcome


def wishpond(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Wishpond"], 1):
		outcome = ["Wishpond Takeover", domain, CNAME]

	return outcome


def aftership(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Aftership"], 1):
		outcome = ["Aftership Takeover", domain, CNAME]

	return outcome


def aha(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Aha!"], 1):
		outcome = ["Aha! Takeover", domain, CNAME]

	return outcome


def tictail(domain, ARecords, CNAME):
	outcome = []

	try:
		if signatures["Tictail"] in str(get("http://" + domain, headers=headers, verify=False).history[0].content, "utf-8"):
			outcome = ["Tictail Takeover", domain, CNAME]
			return outcome

		if signatures["Tictail"] in str(get("https://" + domain, headers=headers, verify=False).history[0].content, "utf-8"):
			outcome = ["Tictail Takeover", domain, CNAME]
			return outcome

	except Exception:
		pass

	return outcome


def brightcove(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Brightcove"], 1):
		outcome = ["Brightcove Takeover", domain, CNAME]

	return outcome


def bigcartel(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Bigcartel"], 1):
		outcome = ["Bigcartel Takeover", domain, CNAME]

	return outcome


def acquia(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Acquia"], 1):
		outcome = ["Acquia Takeover", domain, CNAME]

	return outcome


def simplebooklet(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Simplebooklet"], 1):
		outcome = ["Simplebooklet Takeover", domain, CNAME]

	return outcome


def getresponse(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Getresponse"], 1):
		outcome = ["Getresponse Takeover", domain, CNAME]

	return outcome


def vend(domain, ARecords, CNAME):
	outcome = []

	if findSignatures(domain, signatures["Vend"], 1):
		outcome = ["Vend Takeover", domain, CNAME]

	return outcome


def maxcdn(domain, ARecords, CNAME):
	outcome = []

	if findNX(CNAME):
		outcome = ["Maxcdn Takeover", domain, CNAME]

	return outcome


def apigee(domain, ARecords, CNAME):
	outcome = []

	if findNX(CNAME):
		outcome = ["Apigee Takeover", domain, CNAME]

	return outcome


def identify(domain, ARecords, CNAMERecords):
	outcome = []

	for entry in CNAMERecords:
		CNAME = str(entry)[:-1]

		if (re.findall(".*s3.*.amazonaws\.com", CNAME)):
			outcome = amazonS3(domain, ARecords, CNAME)

		elif "bitbucket.io" in CNAME:
			outcome = bitbucket(domain, ARecords, CNAME)

		elif "createsend.com" in CNAME:
			outcome = campaignMonitor(domain, ARecords, CNAME)

		elif "cargocollective.com" in CNAME:
			outcome = cargoCollective(domain, ARecords, CNAME)

		elif "herokuapp.com" in CNAME:
			outcome = heroku(domain, ARecords, CNAME)

		elif "redirect.feedpress.me" in CNAME:
			outcome = feedpress(domain, ARecords, CNAME)

		elif "ghost.io" in CNAME:
			outcome = ghost(domain, ARecords, CNAME)

		elif "github.io" in CNAME:
			outcome = github(domain, ARecords, CNAME)

		elif "helpjuice.com" in CNAME:
			outcome = helpjuice(domain, ARecords, CNAME)

		elif "helpscoutdocs.com" in CNAME:
			outcome = helpscout(domain, ARecords, CNAME)

		elif "myjetbrains.com" in CNAME:
			outcome = jetbrains(domain, ARecords, CNAME)

		elif "readme.io" in CNAME:
			outcome = readme(domain, ARecords, CNAME)

		elif "surge.sh" in CNAME:
			outcome = surge(domain, ARecords, CNAME)

		elif "domains.tumblr.com" in CNAME:
			outcome = tumblr(domain, ARecords, CNAME)

		elif "uservoice.com" in CNAME:
			outcome = uservoice(domain, ARecords, CNAME)

		elif "domains.smugmug.com" in CNAME:
			outcome = smugmug(domain, ARecords, CNAME)

		elif "s.strikinglydns.com" in CNAME:
			outcome = strikingly(domain, ARecords, CNAME)

		elif "stats.uptimerobot.com" in CNAME:
			outcome = uptimerobot(domain, ARecords, CNAME)

		elif "pantheonsite.io" in CNAME:
			outcome = pantheon(domain, ARecords, CNAME)

		elif "teamwork.com" in CNAME:
			outcome = teamwork(domain, ARecords, CNAME)

		elif "custom.intercom.help" in CNAME:
			outcome = intercom(domain, ARecords, CNAME)

		elif "wishpond.com" in CNAME:
			outcome = wishpond(domain, ARecords, CNAME)

		elif "aftership.com" in CNAME:
			outcome = aftership(domain, ARecords, CNAME)

		elif "ideas.aha.io" in CNAME:
			outcome = aha(domain, ARecords, CNAME)

		elif "domains.tictail.com" in CNAME:
			outcome = tictail(domain, ARecords, CNAME)

		elif "bigcartel.com" in CNAME:
			outcome = bigcartel(domain, ARecords, CNAME)

		elif "simplebooklet.com" in CNAME:
			outcome = simplebooklet(domain, ARecords, CNAME)

		elif ".gr8.com" in CNAME:
			outcome = getresponse(domain, ARecords, CNAME)

		elif "vendecommerce.com" in CNAME:
			outcome = vend(domain, ARecords, CNAME)

		elif "netdna-cdn.com" in CNAME:
			outcome = maxcdn(domain, ARecords, CNAME)

		elif "-portal.apigee.net" in CNAME:
			outcome = apigee(domain, ARecords, CNAME)

		elif "acquia-test.co" in CNAME or "acquia-sites.com" in CNAME:
			outcome = acquia(domain, ARecords, CNAME)

		elif "bcvp0rtal.com" in CNAME or "brightcovegallery.com" in CNAME or "gallery.video" in CNAME or "cloudfront.net" in CNAME:
			outcome = brightcove(domain, ARecords, CNAME)

		elif "proxy.webflow.com" in CNAME or "proxy-ssl.webflow.com" in CNAME:
			outcome = webflow(domain, ARecords, CNAME)

		elif "wordpress.com" in CNAME:
			outcome = wordpress(domain, ARecords, CNAME)

		elif any(azureSub in CNAME for azureSub in [
			"azure-api.net", "azurecontainer.io", "azurecr.io", "azuredatalakestore.net", "azureedge.net", "azurehdinsight.net",
			"azurewebsites.net", "blob.core.windows.net", "cloudapp.azure.com", "cloudapp.net", "database.windows.net",
			"redis.cache.windows.net", "search.windows.net", "servicebus.windows.net", "trafficmanager.net", "visualstudio.com"]):
			outcome = azure(domain, ARecords, CNAME)

	for entry in ARecords:
		if str(entry) == "66.6.44.4":
			outcome = tumblr(domain, ARecords, str(entry))

		elif str(entry) == "185.203.72.17":
			outcome = tilda(domain, ARecords, str(entry))

		elif str(entry) == "46.137.181.142":
			outcome = tictail(domain, ARecords, str(entry))

		elif str(entry) == "54.183.102.22":
			outcome = strikingly(domain, ARecords, str(entry))

		elif str(entry) == "34.193.69.252" or str(entry) == "34.193.204.92" or str(entry) == "23.235.33.229" or str(entry) == "104.156.81.229":
			outcome = webflow(domain, ARecords, str(entry))

		elif "23.185.0." in str(entry) or "23.253." in str(entry):
			outcome = pantheon(domain, ARecords, str(entry))

		elif str(entry) in ["192.30.252.153", "192.30.252.154"]:
			outcome = github(domain, ARecords, str(entry))

	return outcome


def takeOver(domain):
	CNAME = []
	A = []
	results = []
	resolver = Resolver()
	resolver.timeout = 1
	resolver.lifetime = 1
	rrtypes = ["A", "CNAME"]

	for r in rrtypes:
		try:
			answers = resolver.query(domain, r)

			for answer in answers:
				if r == "A":
					A.append(answer.address)

				if r == "CNAME":
					CNAME.append(answer.target)

		except (NXDOMAIN, NoAnswer, EmptyLabel, NoNameservers, Timeout, DNSException):
			pass

		except Exception:
			return None

	results = identify(domain, A, CNAME)
	return results


def massTakeOver(targets, threads):
	takeovers = []
	leaveFlag = False

	if len(targets) <= 100000:
		print("{0} {1} {2}".format(colored("\n[*]-Scanning", "yellow"), colored(len(targets), "cyan"), colored("domains for potential takeover...", "yellow")))
	else:
		print("{0} {1} {2}".format(colored("\n[*]-Scanning", "yellow"), colored(len(targets), "cyan"), colored("domains for potential takeover, in chunks of 100,000...", "yellow")))

	targetChunks = list(utilities.MiscHelpers.chunks(list(targets), 100000))
	iteration = 1

	for targetChunk in targetChunks:
		with ThreadPoolExecutor(max_workers=threads) as executor:
			tasks = {executor.submit(takeOver, target) for target in targetChunk}

			try:
				completed = as_completed(tasks)

				if iteration == len(targetChunks):
					leaveFlag = True

				completed = tqdm(completed, total=len(targetChunk), desc="  \__ {0}".format(colored("Progress", "cyan")), dynamic_ncols=True, leave=leaveFlag)

				for task in completed:
					result = task.result()

					if result is not None:
						takeovers.append(result)

			except KeyboardInterrupt:
				completed.close()
				print(colored("\n[*]-Received keyboard interrupt! Shutting down...\n", "red"))
				executor.shutdown(wait=False)
				exit(-1)

		if iteration < len(targetChunks):
			sys.stderr.write("\033[F")

		iteration += 1

	return takeovers


def init(domain, resolved, collector_hosts, threads, out_to_json):
	resolved_hosts = []

	for host in resolved:
		resolved_hosts.append(host)

	toTakeOver = utilities.MiscHelpers.uniqueList(resolved_hosts + collector_hosts)

	results = massTakeOver(toTakeOver, threads)
	results_json = {}

	for result in results:
		if result:
			results_json[result[1]] = [result[0], result[2]]

	print("    \__ {0} {1}".format(colored("Takeover vulnerabilities that were identified:", "yellow"), colored(len(results_json), "cyan")))

	for key, values in list(results_json.items()):
		print("      \__", colored(key, "cyan"), ":", ", ".join(colored(str(value), "yellow") for value in values))

	if out_to_json:
		try:
			with open(join("results", domain, "takeovers.json"), "w") as takeover_file:
				takeover_file.write("{0}\n".format(dumps(results_json)))

		except OSError:
			pass

		except IOError:
			pass

	try:
		with open(join("results", domain, "takeovers.csv"), "w") as takeover_file:
			for key, values in list(results_json.items()):
				takeover_file.write("{0}|{1}\n".format(key, "|".join(str(value) for value in values)))

	except OSError as ex:
		print(ex)

	except IOError as ex:
		print(ex)
