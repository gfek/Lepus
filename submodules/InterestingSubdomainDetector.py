from termcolor import colored
import utilities.DatabaseHelpers
import os
import csv

# List of keywords to identify interesting subdomains
INTERESTING_KEYWORDS = [
    "admin", "api", "auth", "backup", "beta", "blog", "cdn", "ci", "cms", "config",
    "dashboard", "db", "dev", "docker", "docs", "files", "ftp", "git", "grafana",
    "internal", "jenkins", "jira", "kibana", "ldap", "logs", "mail", "mongo",
    "monitor", "mysql", "nexus", "oauth", "owa", "payment", "phpmyadmin", "portal",
    "prod", "prometheus", "proxy", "pypi", "qa", "redis", "remote", "repo", "s3",
    "sftp", "sql", "ssh", "stage", "staging", "stats", "support", "svn", "test",
    "tfs", "uat", "upload", "vpn", "webmail", "wordpress"
]

def init(db, domain):
    print(colored("\n[*]-Detecting interesting subdomains...", "yellow"))

    # Get all resolved subdomains from the database
    resolved_subdomains = []
    try:
        # Assuming a function to get resolved subdomains from the database
        # This function needs to be implemented in DatabaseHelpers.py
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    interesting_subdomains = []
    for subdomain in resolved_subdomains:
        for keyword in INTERESTING_KEYWORDS:
            if keyword in subdomain:
                interesting_subdomains.append(subdomain)
                break

    if interesting_subdomains:
        print(colored("  \__ Found the following interesting subdomains:", "green"))
        for subdomain in interesting_subdomains:
            print(colored(f"    - {subdomain}", "cyan"))

        # Save results to CSV
        findings_dir = os.path.join("findings", domain)
        os.makedirs(findings_dir, exist_ok=True)
        csv_path = os.path.join(findings_dir, "interesting_subdomains.csv")

        with open(csv_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["subdomain"])
            for subdomain in interesting_subdomains:
                writer.writerow([subdomain])

        print(colored(f"  \__ Results saved to {csv_path}", "blue"))
    else:
        print(colored("  \__ No interesting subdomains found.", "red"))
