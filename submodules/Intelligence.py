import os
import csv
import json
import requests
from termcolor import colored
from datetime import datetime, timedelta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = "kev_cache.json"
CACHE_DURATION_HOURS = 24

def get_kev_data():
    """
    Fetches CISA Known Exploited Vulnerabilities (KEV) data, using a local cache.
    """
    try:
        if os.path.exists(KEV_CACHE_FILE):
            cache_mod_time = datetime.fromtimestamp(os.path.getmtime(KEV_CACHE_FILE))
            if datetime.now() - cache_mod_time < timedelta(hours=CACHE_DURATION_HOURS):
                with open(KEV_CACHE_FILE, 'r') as f:
                    return json.load(f)

        print(colored("  \__ Fetching latest CISA KEV catalog...", "blue"))
        response = requests.get(KEV_URL, timeout=15)
        response.raise_for_status()
        kev_data = response.json()
        with open(KEV_CACHE_FILE, 'w') as f:
            json.dump(kev_data, f)
        return kev_data
    except requests.RequestException as e:
        print(colored(f"  \__ Could not fetch CISA KEV catalog: {e}", "red"))
        if os.path.exists(KEV_CACHE_FILE):
            print(colored("  \__ Using potentially outdated cache.", "yellow"))
            with open(KEV_CACHE_FILE, 'r') as f:
                return json.load(f)
        return None

def init(domain):
    print(colored("[*]-Starting intelligence correlation...", "yellow"))
    
    findings_dir = os.path.join("findings", domain)
    if not os.path.exists(findings_dir):
        print(colored(f"  \__ Findings directory for {domain} not found.", "red"))
        return

    kev_data = get_kev_data()
    kev_cves = {vuln['cveID'] for vuln in kev_data.get('vulnerabilities', [])} if kev_data else set()

    # Placeholder for where we'll store the data from CSVs
    interesting_subdomains = []
    technologies = {}
    vulnerabilities = []
    sensitive_files = []

    # Read interesting subdomains
    try:
        with open(os.path.join(findings_dir, 'interesting_subdomains.csv'), 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            interesting_subdomains = [row[0] for row in reader]
    except FileNotFoundError:
        print(colored("  \__ 'interesting_subdomains.csv' not found, skipping.", "yellow"))

    # Read technologies
    try:
        with open(os.path.join(findings_dir, 'technologies_deep.csv'), 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                subdomain = row.get('subdomain')
                tech = row.get('technology')
                if subdomain not in technologies:
                    technologies[subdomain] = []
                technologies[subdomain].append(tech)
    except FileNotFoundError:
        print(colored("  \__ 'technologies_deep.csv' not found, skipping.", "yellow"))

    # Read vulnerabilities
    try:
        with open(os.path.join(findings_dir, 'vulnerabilities.csv'), 'r') as f:
            reader = csv.DictReader(f)
            # This is a hack to handle the inconsistent JSON from nuclei
            for row in reader:
                try:
                    info_dict = json.loads(row.get('info', '{}').replace("'", '"'))
                    row['info'] = info_dict
                    vulnerabilities.append(row)
                except json.JSONDecodeError:
                    # Fallback for when info is not a valid json string
                    row['info'] = {'name': 'N/A', 'severity': 'info'}
                    vulnerabilities.append(row)

    except FileNotFoundError:
        print(colored("  \__ 'vulnerabilities.csv' not found, skipping.", "yellow"))

    # Read sensitive files
    try:
        with open(os.path.join(findings_dir, 'sensitive_files.csv'), 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            sensitive_files = [row[0] for row in reader]
    except FileNotFoundError:
        print(colored("  \__ 'sensitive_files.csv' not found, skipping.", "yellow"))

    # Correlation Logic
    report = generate_report(domain, interesting_subdomains, technologies, vulnerabilities, sensitive_files, kev_cves)
    
    report_path = os.path.join(findings_dir, f"{domain}_Threat_Report.md")
    with open(report_path, 'w') as f:
        f.write(report)

    print(colored(f"[*]-Intelligence report generated: {report_path}", "green"))

def generate_report(domain, interesting, techs, vulns, sensitive, kev_cves):
    report = f"# Lepus Intelligence Report for {domain}\n"
    report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    critical_findings = []
    high_findings = []
    medium_findings = []

    all_subdomains = set(interesting) | set(techs.keys())
    for v in vulns:
        host = v.get('host', '').replace('https://', '').replace('http://', '').split(':')[0]
        all_subdomains.add(host)
    for u in sensitive:
        host = u.replace('https://', '').replace('http://', '').split('/')[0]
        all_subdomains.add(host)

    for sub in all_subdomains:
        score = 0
        reasons = []

        if sub in interesting:
            score += 10
            reasons.append("Flagged as 'interesting' due to keywords (e.g., admin, api, dev).")

        sub_vulns = [v for v in vulns if sub in v.get('host', '')]
        for v in sub_vulns:
            info = v.get('info', {})
            name = info.get('name', 'N/A')
            severity = info.get('severity', 'info')
            cve_id = info.get('cve-id')
            matched_at = v.get('matched-at', 'N/A')

            is_kev = cve_id and cve_id in kev_cves
            
            if is_kev:
                score += 100 # Escalate to critical
                reasons.append(f"**🔥 ACTIVELY EXPLOITED (CISA KEV):** {name} ({cve_id}) at {matched_at}")
            elif severity == 'critical':
                score += 50
                reasons.append(f"**Critical Vulnerability:** {name} at {matched_at}")
            elif severity == 'high':
                score += 30
                reasons.append(f"**High Vulnerability:** {name} at {matched_at}")
            elif severity == 'medium':
                score += 10
                reasons.append(f"Medium Vulnerability: {name} at {matched_at}")

        sub_sensitive = [s for s in sensitive if sub in s]
        if sub_sensitive:
            score += 25
            reasons.append(f"Exposes sensitive files: {', '.join(sub_sensitive)}")

        sub_techs = techs.get(sub, [])
        if any("Jenkins" in t for t in sub_techs) or any("phpMyAdmin" in t for t in sub_techs):
            score += 15
            reasons.append(f"Running potentially risky technology: {', '.join(sub_techs)}")

        if score >= 100:
             critical_findings.append({'subdomain': sub, 'reasons': reasons})
        elif score >= 40:
            high_findings.append({'subdomain': sub, 'reasons': reasons})
        elif score >= 10:
            medium_findings.append({'subdomain': sub, 'reasons': reasons})

    if critical_findings:
        report += "## 🔥 CRITICAL FINDINGS\n"
        for f in sorted(critical_findings, key=lambda x: x['subdomain']):
            report += f"### {f['subdomain']}\n"
            for reason in f['reasons']:
                report += f"- {reason}\n"
            report += "\n"

    if high_findings:
        report += "## HIGH-PRIORITY FINDINGS\n"
        for f in sorted(high_findings, key=lambda x: x['subdomain']):
            report += f"### {f['subdomain']}\n"
            for reason in f['reasons']:
                report += f"- {reason}\n"
            report += "\n"

    if medium_findings:
        report += "## MEDIUM-PRIORITY FINDINGS\n"
        for f in sorted(medium_findings, key=lambda x: x['subdomain']):
            report += f"### {f['subdomain']}\n"
            for reason in f['reasons']:
                report += f"- {reason}\n"
            report += "\n"
            
    if not critical_findings and not high_findings and not medium_findings:
        report += "## No High-Impact Findings\n"
        report += "No significant correlations were found based on the current ruleset.\n"

    return report
