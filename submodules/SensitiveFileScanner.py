import httpx
from termcolor import colored
from tqdm import tqdm
import asyncio
import utilities.DatabaseHelpers
import os
import csv

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

async def check_url(session, sem, subdomain, path, pbar, found_files_queue):
    async with sem:
        url = f"https://{subdomain}{path if path.startswith('/') else '/' + path}"
        try:
            response = await session.get(url, timeout=10, follow_redirects=True)
            if response.status_code == 200:
                tqdm.write(colored(f"  \__ Found sensitive file: {url}", "green"))
                await found_files_queue.put(url)
        except httpx.RequestError:
            pass  # Ignore connection errors, timeouts, etc.
        finally:
            pbar.update(1)

async def main_scanner(domain, subdomains, pbar):
    sem = asyncio.Semaphore(100)  # Limit to 100 concurrent requests
    found_files_queue = asyncio.Queue()
    async with httpx.AsyncClient(verify=False) as session:
        tasks = []
        for subdomain in subdomains:
            if not subdomain or subdomain.isspace():
                tqdm.write(colored(f"  \__ Skipping invalid subdomain: {subdomain}", "red"))
                continue
            for path in SENSITIVE_PATHS:
                tasks.append(check_url(session, sem, subdomain, path, pbar, found_files_queue))
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

    total_requests = len(resolved_subdomains) * len(SENSITIVE_PATHS)
    with tqdm(total=total_requests, desc="Scanning for sensitive files", unit="req") as pbar:
        found_files = await main_scanner(domain, resolved_subdomains, pbar)

    if found_files:
        findings_dir = os.path.join("findings", domain)
        os.makedirs(findings_dir, exist_ok=True)
        csv_path = os.path.join(findings_dir, "sensitive_files.csv")

        with open(csv_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["url"])
            for url in found_files:
                writer.writerow([url])
        
        print(colored(f"  \__ Results saved to {csv_path}", "blue"))
    else:
        print(colored("  \__ No sensitive files found.", "red"))
