import json
from termcolor import colored
import utilities.DatabaseHelpers
import os


def generate_json_report(db, domain):
    print(colored("[*]-Generating JSON report...", "yellow"))

    findings = {}
    try:
        findings = utilities.DatabaseHelpers.getAllFindings(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving findings: {e}", "red"))
        return

    path = os.path.join("findings", domain)
    os.makedirs(path, exist_ok=True)
    report_path = os.path.join(path, f"{domain}.json")

    with open(report_path, "w") as f:
        json.dump(findings, f, indent=4)

    print(colored(f"  \__ JSON report saved to {report_path}", "green"))


def generate_html_report(db, domain):
    print(colored("\n[*]-Generating HTML report...", "yellow"))

    findings = {}
    try:
        findings = utilities.DatabaseHelpers.getAllFindings(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving findings: {e}", "red"))
        return

    path = os.path.join("findings", domain)
    os.makedirs(path, exist_ok=True)
    report_path = os.path.join(path, f"{domain}.html")

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lepus Report for {domain}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #f0883e; margin-top: 30px; }}
  h3 {{ color: #8b949e; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0 20px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
  .badge-green {{ background: #1b6b2e; color: #7ee787; }}
  .badge-red {{ background: #6b1b1b; color: #f85149; }}
  .badge-yellow {{ background: #6b5a1b; color: #d29922; }}
  .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin: 20px 0; }}
  .summary span {{ font-size: 24px; font-weight: 700; margin-right: 10px; }}
  a {{ color: #58a6ff; }}
  .empty {{ color: #8b949e; font-style: italic; }}
</style>
</head>
<body>
<h1>Lepus Reconnaissance Report for {domain}</h1>
<p>Generated: {generated}</p>

<div class="summary">
  <h2>Summary</h2>
  <p>Resolved Subdomains: <span>{resolved_count}</span></p>
  <p>Unresolved Subdomains: <span>{unresolved_count}</span></p>
  <p>Open Ports: <span>{open_port_count}</span></p>
  <p>ASNs Found: <span>{asn_count}</span></p>
  <p>Networks Found: <span>{network_count}</span></p>
  <p>Takeovers Found: <span>{takeover_count}</span></p>
  <p>Technologies Identified: <span>{tech_count}</span></p>
  <p>Sensitive Files: <span>{sensitive_count}</span></p>
  <p>Vulnerabilities: <span>{vuln_count}</span></p>
</div>
""".format(
        domain=domain,
        generated=__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        resolved_count=len(findings.get("resolved_subdomains", [])),
        unresolved_count=len(findings.get("unresolved_subdomains", [])),
        open_port_count=len(findings.get("open_ports", [])),
        asn_count=len(findings.get("asns", [])),
        network_count=len(findings.get("networks", [])),
        takeover_count=len(findings.get("takeovers", [])),
        tech_count=len(findings.get("technologies", [])),
        sensitive_count=len(findings.get("sensitive_files", [])),
        vuln_count=len(findings.get("vulnerabilities", [])),
    )

    # Resolved subdomains
    if findings.get("resolved_subdomains"):
        html += "<h2>Resolved Subdomains</h2><table><tr><th>Subdomain</th><th>Address</th><th>Type</th><th>Source</th></tr>"
        for r in findings["resolved_subdomains"]:
            badge = "badge-red" if r["isWildcard"] else "badge-green"
            html += "<tr><td>{}</td><td>{}</td><td><span class='badge {}'>{}</span></td><td>{}</td></tr>".format(
                r["subdomain"], r["address"], badge,
                "Wildcard" if r["isWildcard"] else "Normal",
                r["source"],
            )
        html += "</table>"
    else:
        html += "<h2>Resolved Subdomains</h2><p class='empty'>None found</p>"

    # Open ports
    if findings.get("open_ports"):
        html += "<h2>Open Ports</h2><table><tr><th>Address</th><th>Port</th><th>SSL</th></tr>"
        for p in findings["open_ports"]:
            html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(p["address"], p["port"], "Yes" if p["isSSL"] else "No")
        html += "</table>"
    else:
        html += "<h2>Open Ports</h2><p class='empty'>None found</p>"

    # Takeovers
    if findings.get("takeovers"):
        html += "<h2>Takeover Vulnerabilities</h2><table><tr><th>Subdomain</th><th>Provider</th><th>Signature</th></tr>"
        for t in findings["takeovers"]:
            html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(t["subdomain"], t["provider"], t["signature"])
        html += "</table>"
    else:
        html += "<h2>Takeover Vulnerabilities</h2><p class='empty'>None found</p>"

    # Technologies
    if findings.get("technologies"):
        from collections import Counter
        tech_counts = Counter(t["technology"] for t in findings["technologies"])
        html += "<h2>Technologies</h2><table><tr><th>Technology</th><th>Count</th></tr>"
        for tech, count in tech_counts.most_common():
            html += "<tr><td>{}</td><td>{}</td></tr>".format(tech, count)
        html += "</table>"
    else:
        html += "<h2>Technologies</h2><p class='empty'>None identified</p>"

    # Sensitive files
    if findings.get("sensitive_files"):
        html += "<h2>Sensitive Files</h2><ul>"
        for sf in findings["sensitive_files"]:
            html += "<li><a href='{}' target='_blank'>{}</a></li>".format(sf["url"], sf["url"])
        html += "</ul>"
    else:
        html += "<h2>Sensitive Files</h2><p class='empty'>None found</p>"

    # Vulnerabilities
    if findings.get("vulnerabilities"):
        html += "<h2>Vulnerabilities</h2><table><tr><th>Subdomain</th><th>URL</th></tr>"
        for v in findings["vulnerabilities"]:
            html += "<tr><td>{}</td><td>{}</td></tr>".format(v["subdomain"], v["url"])
        html += "</table>"
    else:
        html += "<h2>Vulnerabilities</h2><p class='empty'>None found</p>"

    # ASNs
    if findings.get("asns"):
        html += "<h2>Autonomous Systems</h2><table><tr><th>ASN</th><th>Prefix</th><th>Description</th></tr>"
        for a in findings["asns"]:
            html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(a["id"], a["prefix"], a["description"])
        html += "</table>"
    else:
        html += "<h2>Autonomous Systems</h2><p class='empty'>None found</p>"

    html += "</body></html>"

    with open(report_path, "w") as f:
        f.write(html)

    print(colored(f"  \__ HTML report saved to {report_path}", "green"))
