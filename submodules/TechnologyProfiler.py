import subprocess
import json
import re
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import utilities.DatabaseHelpers
import os
import csv
import requests
from bs4 import BeautifulSoup
import time
from packaging import version as version_parser

# High-interest technologies that require special attention
HIGH_INTEREST_TECH = [
    "Jenkins", "Grafana", "Jira", "Wordpress", "phpMyAdmin", "Nexus", "Artifactory",
    "Drupal", "Magento", "SharePoint", "Confluence", "Tomcat", "Apache", "Nginx",
    "IIS", "Docker", "Kubernetes", "Spring Boot", "Express", "Flask", "Django"
]

def get_technologies_deep(hostname):
    """Performs deep technology profiling using multiple tools and techniques."""
    technologies = set()
    errors = []

    # Use httpx for initial tech detection
    try:
        httpx_path = os.path.expanduser("~/go/bin/httpx")
        command = [
            httpx_path,
            "-silent",
            "-tech-detect",
            "-json",
            "-u",
            hostname,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if "tech" in data:
                            technologies.update(data["tech"])
                    except json.JSONDecodeError:
                        pass
        else:
            errors.append(f"httpx error: {result.stderr}")
    except FileNotFoundError:
        errors.append("httpx not found. Please ensure it's in your PATH.")
    except subprocess.TimeoutExpired:
        errors.append("httpx timed out")
    except Exception as e:
        errors.append(f"httpx error: {str(e)}")

    # Use whatweb for additional tech detection
    try:
        command = [
            "whatweb",
            "--color=never",
            "--no-errors",
            hostname,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            output = result.stdout.strip()
            if "Server[" in output:
                match = re.search(r"Server\[([^\]]+)\]", output)
                if match:
                    technologies.add(f"Server:{match.group(1)}")

            if "X-Powered-By[" in output:
                match = re.search(r"X-Powered-By\[([^\]]+)\]", output)
                if match:
                    technologies.add(f"X-Powered-By:{match.group(1)}")
        else:
            errors.append(f"whatweb error: {result.stderr}")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        errors.append("whatweb timed out")
    except Exception as e:
        errors.append(f"whatweb error: {str(e)}")

    # Use nmap for service detection (if available)
    try:
        command = [
            "nmap",
            "-p80,443",
            "--script=http-headers,http-server-header",
            "--open",
            hostname,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            output = result.stdout
            if "Server:" in output:
                match = re.search(r"Server:\s*(.+)", output)
                if match:
                    technologies.add(f"Server:{match.group(1).strip()}")
        else:
            errors.append(f"nmap error: {result.stderr}")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        errors.append("nmap timed out")
    except Exception as e:
        errors.append(f"nmap error: {str(e)}")

    return list(technologies), errors

def extract_version(tech_string):
    """Extract version number from technology string."""
    match = re.search(r"[\d]+(?:\.[\d]+)*", tech_string)
    if match:
        return match.group(0)
    return None

def analyze_technologies_deep(hostname, technologies):
    """Analyzes technologies to find versions and high-interest keywords."""
    analysis_results = {
        "high_interest": [],
        "versions": {}
    }

    for tech in technologies:
        tech_parts = tech.split(":")
        tech_name = tech_parts[0] if tech_parts else tech

        for high_interest in HIGH_INTEREST_TECH:
            if re.search(high_interest, tech_name, re.IGNORECASE):
                analysis_results["high_interest"].append(tech)
                break

        version = extract_version(tech)
        if version:
            analysis_results["versions"][tech] = version

    return analysis_results

def process_subdomain(subdomain, domain):
    """Constructs the FQDN and initiates deep technology profiling and analysis."""
    if not subdomain or subdomain.isspace():
        return None, None, None, "Empty or whitespace subdomain"

    hostname = subdomain
    if not subdomain.endswith(f".{domain}") and subdomain != domain:
        hostname = f"{subdomain}.{domain}"

    technologies, errors = get_technologies_deep(hostname)

    if errors:
        error_msg = "; ".join(errors)
        return hostname, None, None, error_msg

    if not technologies:
        return hostname, None, None, "No technologies detected"

    analysis = analyze_technologies_deep(hostname, technologies)
    return hostname, technologies, analysis, None

def init(db, domain):
    print(colored("\n[*]-Performing deep technology profiling and analysis...", "yellow"))

    try:
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    if not resolved_subdomains:
        print(colored("  \__ No resolved subdomains found for technology profiling.", "red"))
        return

    all_findings = []
    processed_count = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(process_subdomain, sub, domain): sub for sub in resolved_subdomains}

        for future in as_completed(futures):
            hostname, technologies, analysis, error = future.result()
            processed_count += 1

            if error:
                print(colored(f"  \__ Error profiling {hostname}: {error}", "red"))
            elif technologies:
                print(colored(f"  \__ {hostname}:", "green"))
                for tech in technologies:
                    print(colored(f"    - {tech}", "cyan"))

                if analysis and (analysis["high_interest"] or analysis["versions"]):
                    print(colored("    Actionable Intelligence:", "magenta"))

                    if analysis["high_interest"]:
                        for item in analysis["high_interest"]:
                            print(colored(f"      [!] High-Interest: {item}", "yellow"))

                    if analysis["versions"]:
                        for tech, version in analysis["versions"].items():
                            print(colored(f"      [i] Version Detected: {tech} ({version})", "blue"))

                # Store findings
                for tech in technologies:
                    finding = {
                        "subdomain": hostname,
                        "technology": tech,
                        "high_interest": "No",
                        "version": "",
                    }

                    if analysis:
                        if tech in analysis.get("high_interest", []):
                            finding["high_interest"] = "Yes"
                        if tech in analysis.get("versions", {}):
                            finding["version"] = analysis["versions"][tech]

                    all_findings.append(finding)

            if processed_count % 10 == 0:
                print(colored(f"  \__ Processed {processed_count}/{len(resolved_subdomains)} subdomains...", "blue"))

    if all_findings:
        findings_dir = os.path.join("findings", domain)
        os.makedirs(findings_dir, exist_ok=True)
        csv_path = os.path.join(findings_dir, "technologies_deep.csv")

        with open(csv_path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["subdomain", "technology", "high_interest", "version"])
            writer.writeheader()
            writer.writerows(all_findings)

        print(colored(f"  \__ Deep technology profiling results saved to {csv_path}", "blue"))
        print(colored(f"  \__ Total technologies identified: {len(all_findings)}", "green"))
    else:
        print(colored("  \__ No technologies found.", "red"))