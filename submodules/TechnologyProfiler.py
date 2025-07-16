import subprocess
import json
import re
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import utilities.DatabaseHelpers
import os
import csv
from default_api import google_web_search

HIGH_INTEREST_TECH = [
    "Jenkins", "Grafana", "Jira", "Wordpress", "phpMyAdmin", "Nexus", "Artifactory"
]

def get_technologies(hostname):
    """Analyzes HTTP headers to identify server technologies using httpx."""
    try:
        command = [
            os.path.expanduser("~/go/bin/httpx"),
            "-silent",
            "-tech-detect",
            "-json",
            "-u",
            hostname,
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        technologies = []
        for line in result.stdout.strip().split('\n'):
            if line:
                data = json.loads(line)
                if "tech" in data:
                    technologies.extend(data["tech"])
        
        return hostname, technologies, None
    except FileNotFoundError:
        return hostname, None, "httpx not found. Please ensure it's in your PATH."
    except subprocess.CalledProcessError as e:
        return hostname, None, f"httpx error: {e.stderr}"
    except json.JSONDecodeError:
        return hostname, None, "Failed to parse httpx JSON output."
    except Exception as e:
        return hostname, None, str(e)

def analyze_technologies(hostname, technologies):
    """Analyzes technologies to find versions and known vulnerabilities."""
    analysis_results = {
        "high_interest": [],
        "cves": {},
    }

    for tech in technologies:
        # Check for high-interest technologies
        for high_interest in HIGH_INTEREST_TECH:
            if re.search(high_interest, tech, re.IGNORECASE):
                analysis_results["high_interest"].append(tech)

        # Extract version numbers and search for CVEs
        match = re.search(r"([\d\.]+)", tech)
        if match:
            version = match.group(1)
            tech_name = tech.split(':')[0]
            search_query = f'{tech_name} {version} CVE'
            try:
                cve_results = google_web_search(query=search_query)
                if cve_results and cve_results.get("results"):
                    analysis_results["cves"][tech] = [result['url'] for result in cve_results["results"][:3]]
            except Exception as e:
                print(colored(f"  \__ Error searching for CVEs for {tech}: {e}", "red"))

    return analysis_results

def process_subdomain(subdomain, domain):
    """Constructs the FQDN and initiates technology profiling and analysis."""
    if not subdomain or subdomain.isspace():
        return None, None, None, "Empty or whitespace subdomain"

    hostname = subdomain
    if not subdomain.endswith(f".{domain}") and subdomain != domain:
        hostname = f"{subdomain}.{domain}"

    hostname, technologies, error = get_technologies(hostname)
    if error or not technologies:
        return hostname, None, None, error

    analysis = analyze_technologies(hostname, technologies)
    return hostname, technologies, analysis, None

def init(db, domain):
    print(colored("\n[*]-Performing advanced technology profiling and analysis...", "yellow"))

    try:
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_subdomain, sub, domain): sub for sub in resolved_subdomains}
        for future in as_completed(futures):
            hostname, technologies, analysis, error = future.result()
            if error:
                print(colored(f"  \__ Error profiling {hostname}: {error}", "red"))
            elif technologies:
                print(colored(f"  \__ {hostname}:", "green"))
                for tech in technologies:
                    print(colored(f"    - {tech}", "cyan"))
                
                if analysis and (analysis["high_interest"] or analysis["cves"]):
                    print(colored("    Actionable Intelligence:", "magenta"))
                    if analysis["high_interest"]:
                        for item in analysis["high_interest"]:
                            print(colored(f"      [!] High-Interest: {item}", "yellow"))
                    if analysis["cves"]:
                        for tech, cves in analysis["cves"].items():
                            print(colored(f"      [!] Potential CVEs for {tech}:", "red"))
                            for cve in cves:
                                print(colored(f"        - {cve}", "red"))
                
                for tech in technologies:
                    finding = {"subdomain": hostname, "technology": tech, "high_interest": "", "cves": ""}
                    if analysis and tech in analysis.get("high_interest", []):
                        finding["high_interest"] = "Yes"
                    if analysis and tech in analysis.get("cves", {}):
                        finding["cves"] = ", ".join(analysis["cves"][tech])
                    all_findings.append(finding)

    if all_findings:
        findings_dir = os.path.join("findings", domain)
        os.makedirs(findings_dir, exist_ok=True)
        csv_path = os.path.join(findings_dir, "technologies_advanced.csv")

        with open(csv_path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["subdomain", "technology", "high_interest", "cves"])
            writer.writeheader()
            writer.writerows(all_findings)

        print(colored(f"  \__ Advanced results saved to {csv_path}", "blue"))
    else:
        print(colored("  \__ No technologies found.", "red"))