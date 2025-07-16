import os
import csv
import json
import requests
from termcolor import colored
from datetime import datetime, timedelta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = "kev_cache.json"
CACHE_DURATION_HOURS = 24


# === Enhancement: Add mapping of tech to common CVEs ===
TECH_CVE_MAP = {
    "Jenkins": ["CVE-2023-27898", "CVE-2020-2100"],
    "phpMyAdmin": ["CVE-2018-12613"],
    "Apache": ["CVE-2021-41773"],
    "Tomcat": ["CVE-2020-9484"],
    "Drupal": ["CVE-2018-7600"],
    "WordPress": ["CVE-2022-21661"]
}

def get_kev_data():
    try:
        if os.path.exists(KEV_CACHE_FILE):
            cache_mod_time = datetime.fromtimestamp(os.path.getmtime(KEV_CACHE_FILE))
            if datetime.now() - cache_mod_time < timedelta(hours=CACHE_DURATION_HOURS):
                with open(KEV_CACHE_FILE, 'r') as f:
                    return json.load(f)

        print(colored("  \\__ Fetching latest CISA KEV catalog...", "blue"))
        response = requests.get(KEV_URL, timeout=15)
        response.raise_for_status()
        kev_data = response.json()
        with open(KEV_CACHE_FILE, 'w') as f:
            json.dump(kev_data, f)
        return kev_data
    except requests.RequestException as e:
        print(colored(f"  \\__ Could not fetch CISA KEV catalog: {e}", "red"))
        if os.path.exists(KEV_CACHE_FILE):
            print(colored("  \\__ Using potentially outdated cache.", "yellow"))
            with open(KEV_CACHE_FILE, 'r') as f:
                return json.load(f)
        return None

def init(domain):
    print(colored("[*]-Starting intelligence correlation...", "yellow"))

    findings_dir = os.path.join("findings", domain)
    if not os.path.exists(findings_dir):
        print(colored(f"  \\__ Findings directory for {domain} not found.", "red"))
        return

    kev_data = get_kev_data()
    kev_cves = {vuln['cveID'] for vuln in kev_data.get('vulnerabilities', [])} if kev_data else set()

    interesting_subdomains = []
    technologies = {}
    vulnerabilities = []
    sensitive_files = []

    try:
        with open(os.path.join(findings_dir, 'interesting_subdomains.csv'), 'r') as f:
            reader = csv.reader(f)
            next(reader)
            interesting_subdomains = [row[0] for row in reader]
    except FileNotFoundError:
        print(colored("  \\__ 'interesting_subdomains.csv' not found, skipping.", "yellow"))

    try:
        with open(os.path.join(findings_dir, 'technologies.csv'), 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                subdomain = row.get('subdomain')
                tech = row.get('technology')
                if subdomain not in technologies:
                    technologies[subdomain] = []
                technologies[subdomain].append(tech)
    except FileNotFoundError:
        print(colored("  \\__ 'technologies.csv' not found, skipping.", "yellow"))

    try:
        with open(os.path.join(findings_dir, 'vulnerabilities.csv'), 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    info_dict = json.loads(row.get('info', '{}').replace("'", '"'))
                    row['info'] = info_dict
                    vulnerabilities.append(row)
                except json.JSONDecodeError:
                    row['info'] = {'name': 'N/A', 'severity': 'info'}
                    vulnerabilities.append(row)
    except FileNotFoundError:
        print(colored("  \\__ 'vulnerabilities.csv' not found, skipping.", "yellow"))

    try:
        with open(os.path.join(findings_dir, 'sensitive_files.csv'), 'r') as f:
            reader = csv.reader(f)
            next(reader)
            sensitive_files = [row[0] for row in reader]
    except FileNotFoundError:
        print(colored("  \\__ 'sensitive_files.csv' not found, skipping.", "yellow"))

    report = generate_report(domain, interesting_subdomains, technologies, vulnerabilities, sensitive_files, kev_cves)
    report_path = os.path.join(findings_dir, f"{domain}_Threat_Report.md")
    with open(report_path, 'w') as f:
        f.write(report)

    print(colored(f"[*]-Intelligence report generated: {report_path}", "green"))

def generate_report(domain, interesting, techs, vulns, sensitive, kev_cves):
    report = f"# Lepus Intelligence Report for {domain}\n"
    report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    critical_findings, high_findings, medium_findings = [], [], []
    all_subdomains = set(interesting) | set(techs.keys())

    for v in vulns:
        host = v.get('host', '').replace('https://', '').replace('http://', '').split(':')[0]
        all_subdomains.add(host)
    for u in sensitive:
        host = u.replace('https://', '').replace('http://', '').split('/')[0]
        all_subdomains.add(host)

    for sub in all_subdomains:
        score, reasons = 0, []

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
                score += 100
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
        for tech in sub_techs:
            if tech in TECH_CVE_MAP:
                for cve in TECH_CVE_MAP[tech]:
                    if cve in kev_cves:
                        score += 75
                        reasons.append(f"**🔥 {tech} maps to known exploited CVE ({cve}) in CISA KEV.")
            elif any(x in tech for x in ["Jenkins", "phpMyAdmin"]):
                score += 15
                reasons.append(f"Running potentially risky technology: {', '.join(sub_techs)}")

        finding = {'subdomain': sub, 'reasons': reasons}
        if score >= 100:
            critical_findings.append(finding)
        elif score >= 40:
            high_findings.append(finding)
        elif score >= 10:
            medium_findings.append(finding)

    def format_findings(label, items):
        section = f"## {label}\n"
        for f in sorted(items, key=lambda x: x['subdomain']):
            section += f"### {f['subdomain']}\n"
            for reason in f['reasons']:
                section += f"- {reason}\n"
            section += "\n"
        return section

    if critical_findings:
        report += format_findings("🔥 CRITICAL FINDINGS", critical_findings)
    if high_findings:
        report += format_findings("HIGH-PRIORITY FINDINGS", high_findings)
    if medium_findings:
        report += format_findings("MEDIUM-PRIORITY FINDINGS", medium_findings)
    if not (critical_findings or high_findings or medium_findings):
        report += "## No High-Impact Findings\nNo significant correlations were found based on the current ruleset.\n"

    return report
