import httpx
from termcolor import colored
from tqdm import tqdm
import asyncio
import utilities.DatabaseHelpers
import os
import csv
from bs4 import BeautifulSoup

# List of sensitive file paths to check for
SENSITIVE_PATHS = [
    ".bak", ".config", ".conf", ".ini", ".log", ".sql", ".zip", ".tar.gz", ".tgz",
    ".rar", ".7z", ".bz2", ".gz", ".tar", ".swp", ".swo", ".db", ".mdb", ".sqlite",
    ".sqlitedb", ".csv", ".json", ".xml", ".yaml", ".yml", ".pem", ".key", ".p12",
    ".pfx", ".cer", ".crt", ".der", ".jks", ".keystore", ".p7b", ".p7c", ".p7s",
    ".p8", ".csr", ".crl", ".asc", ".gpg", ".kdb", ".sdb", ".psafe3", ".agilekeychain",
    ".keychain", ".pbe", ".wallet", ".dat", ".kdbx", ".safe", ".gnucash", ".ovpn",
    ".rdp", ".ppk", ".pub", ".known_hosts", ".bash_history", ".zsh_history",
    ".history", ".sh_history", ".mysql_history", ".psql_history", ".dbeaver-data-sources.xml",
    ".pgpass", ".npmrc", ".yarnrc", ".git-credentials", ".netrc", ".aws/credentials",
    ".s3cfg", ".boto", ".google/gce.json", ".gcloud/credentials.db", ".docker/config.json",
    ".kube/config", ".heroku/credentials", ".travis.yml", ".circleci/config.yml",
    ".gitlab-ci.yml", ".jenkins.xml", ".deploy.sh", ".env", ".env.local", ".env.dev",
    ".env.prod", ".env.stage", ".env.test", ".env.example", ".env.sample", ".env.dist",
    ".env.secret", ".env.secrets", ".env.production", ".env.development", ".env.staging",
    ".env.testing", ".env.uat", ".env.prod.local", ".env.dev.local", ".env.stage.local",
    ".env.test.local", ".env.uat.local", ".env.production.local", ".env.development.local",
    ".env.staging.local", ".env.testing.local", ".env.uat.local", ".env.prod.secret",
    ".env.dev.secret", ".env.stage.secret", ".env.test.secret", ".env.uat.secret",
    ".env.production.secret", ".env.development.secret", ".env.staging.secret",
    ".env.testing.secret", ".env.uat.secret", "/.git/config", "/.svn/entries",
    "/.hg/hgrc", "/CVS/Root", "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
    "/WEB-INF/classes/application.properties", "/WEB-INF/database.properties",
    "/WEB-INF/spring-security.xml", "/WEB-INF/security.xml", "/WEB-INF/struts-config.xml",
    "/WEB-INF/ejb-jar.xml", "/WEB-INF/ibm-web-bnd.xmi", "/WEB-INF/ibm-web-ext.xmi",
    "/WEB-INF/ibm-web-bnd.xml", "/WEB-INF/ibm-web-ext.xml", "/WEB-INF/weblogic.xml",
    "/WEB-INF/jboss-web.xml", "/WEB-INF/sun-web.xml", "/WEB-INF/glassfish-web.xml",
    "/WEB-INF/geronimo-web.xml", "/WEB-INF/jetty-web.xml", "/WEB-INF/resin-web.xml",
    "/WEB-INF/oc4j-web.xml", "/WEB-INF/orion-web.xml", "/WEB-INF/application.xml",
    "/WEB-INF/application-client.xml", "/WEB-INF/jboss-deployment-structure.xml",
    "/META-INF/MANIFEST.MF", "/META-INF/application.xml", "/META-INF/ejb-jar.xml",
    "/META-INF/jboss-app.xml", "/META-INF/jboss-web.xml", "/META-INF/jdoconfig.xml",
    "/META-INF/persistence.xml", "/META-INF/context.xml", "/META-INF/application-client.xml",
    "/META-INF/jboss-deployment-structure.xml", "/actuator/env", "/actuator/health",
    "/api/v2/api-docs", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/swagger.yml", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/api/v1/swagger.json",
    "/api/v1/swagger.yaml", "/api/v1/swagger.yml", "/api/v2/swagger.json",
    "/api/v2/swagger.yaml", "/api/v2/swagger.yml", "/api/v3/swagger.json",
    "/api/v3/swagger.yaml", "/api/v3/swagger.yml", "/graphql", "/graphiql",
    "/playground", "/console", "/manage", "/status", "/info", "/metrics", "/dump",
    "/trace", "/mappings", "/autoconfig", "/beans", "/configprops", "/env",
    "/flyway", "/liquibase", "/heapdump", "/jolokia", "/logfile", "/prometheus",
    "/scheduledtasks", "/sessions", "/shutdown", "/threaddump", "/actuator",
    "/actuator/auditevents", "/actuator/beans", "/actuator/caches", "/actuator/conditions",
    "/actuator/configprops", "/actuator/dump", "/actuator/env", "/actuator/flyway",
    "/actuator/health", "/actuator/heapdump", "/actuator/info", "/actuator/jolokia",
    "/actuator/liquibase", "/actuator/logfile", "/actuator/loggers", "/actuator/mappings",
    "/actuator/metrics", "/actuator/prometheus", "/actuator/scheduledtasks",
    "/actuator/sessions", "/actuator/shutdown", "/actuator/threaddump", "/solr/admin/info/system"
]

async def get_homepage_details(session, subdomain):
    """Fetches the content and title of the subdomain's homepage to detect soft 404s."""
    try:
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}/"
            response = await session.get(url, timeout=5, follow_redirects=True)
            if response.status_code == 200:
                content = response.text
                soup = BeautifulSoup(content, 'html.parser')
                title = soup.title.string if soup.title else None
                return content, title
    except (httpx.RequestError, Exception):
        return None, None
    return None, None

async def check_url(session, sem, subdomain, path, pbar, found_files_queue, homepage_content, homepage_title):
    async with sem:
        url = f"https://{subdomain}{path if path.startswith('/') else '/' + path}"
        try:
            response = await session.get(url, timeout=10, follow_redirects=True)
            status = response.status_code

            if status == 200:
                is_soft_404 = False
                if homepage_content and len(response.text) == len(homepage_content):
                    is_soft_404 = True
                
                if not is_soft_404 and homepage_title:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if soup.title and soup.title.string == homepage_title:
                        is_soft_404 = True

                if not is_soft_404:
                    tqdm.write(colored(f"[200 OK] Found sensitive file: {url}", "green"))
                    await found_files_queue.put(url)
            
            

        except (httpx.RequestError, Exception):
            pass
        finally:
            pbar.update(1)

async def pre_screen_subdomain(session, sem, subdomain, live_subdomains_queue):
    async with sem:
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            try:
                response = await session.head(url, timeout=5, follow_redirects=True)
                if response.status_code < 500:
                    await live_subdomains_queue.put(subdomain)
                    return 
            except httpx.RequestError:
                continue 

async def main_scanner(domain, subdomains, pbar):
    sem = asyncio.Semaphore(100)
    found_files_queue = asyncio.Queue()
    async with httpx.AsyncClient(verify=False) as session:
        tasks = []
        for subdomain in subdomains:
            if not subdomain or subdomain.isspace():
                continue
            
            homepage_content, homepage_title = await get_homepage_details(session, subdomain)

            for path in SENSITIVE_PATHS:
                tasks.append(check_url(session, sem, subdomain, path, pbar, found_files_queue, homepage_content, homepage_title))
        await asyncio.gather(*tasks)

    found_files = []
    while not found_files_queue.empty():
        found_files.append(await found_files_queue.get())

    return found_files

async def init(db, domain):
    print(colored("[*]-Scanning for sensitive files...", "yellow"))

    resolved_subdomains = []
    try:
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    if not resolved_subdomains:
        print(colored("  \__ No resolved subdomains found to scan.", "yellow"))
        return

    print(colored("[*]-Pre-screening subdomains for live web servers...", "yellow"))
    live_subdomains_queue = asyncio.Queue()
    sem = asyncio.Semaphore(100)
    async with httpx.AsyncClient(verify=False) as session:
        tasks = [pre_screen_subdomain(session, sem, sub, live_subdomains_queue) for sub in resolved_subdomains]
        with tqdm(total=len(tasks), desc="Pre-screening hosts", unit="host") as pbar:
            for f in asyncio.as_completed(tasks):
                await f
                pbar.update()

    live_subdomains = []
    while not live_subdomains_queue.empty():
        live_subdomains.append(await live_subdomains_queue.get())

    if not live_subdomains:
        print(colored("  \__ No live web servers found to scan.", "red"))
        return

    print(colored(f"\n[*]-Found {len(live_subdomains)} live subdomains. Starting sensitive file scan...", "yellow"))
    total_requests = len(live_subdomains) * len(SENSITIVE_PATHS)
    with tqdm(total=total_requests, desc="Scanning for sensitive files", unit="req") as pbar:
        found_files = await main_scanner(domain, live_subdomains, pbar)

    if found_files:
        findings_dir = os.path.join("findings", domain)
        os.makedirs(findings_dir, exist_ok=True)
        csv_path = os.path.join(findings_dir, "sensitive_files.csv")

        with open(csv_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["url"])
            for url in found_files:
                writer.writerow([url])

        print(colored(f"\n[+] Scan complete. Found {len(found_files)} potential sensitive files.", "green"))
        print(colored(f"  \__ Results saved to {csv_path}", "blue"))
    else:
        print(colored("\n[-] Scan complete. No sensitive files found.", "red"))