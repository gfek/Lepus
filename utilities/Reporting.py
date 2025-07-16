import json
from termcolor import colored
import utilities.DatabaseHelpers

def generate_json_report(db, domain):
    print(colored("[*]-Generating JSON report...", "yellow"))

    # Get all findings from the database
    findings = {}
    try:
        # Assuming a function to get all findings from the database
        # This function needs to be implemented in DatabaseHelpers.py
        findings = utilities.DatabaseHelpers.getAllFindings(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving findings: {e}", "red"))
        return

    # Generate JSON report
    with open(f"{domain}.json", "w") as f:
        json.dump(findings, f, indent=4)

    print(colored(f"  \__ JSON report saved to {domain}.json", "green"))

def generate_html_report(db, domain):
    print(colored("\n[*]-Generating HTML report...", "yellow"))

    # Get all findings from the database
    findings = {}
    try:
        # Assuming a function to get all findings from the database
        # This function needs to be implemented in DatabaseHelpers.py
        findings = utilities.DatabaseHelpers.getAllFindings(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving findings: {e}", "red"))
        return

    # Generate HTML report
    with open(f"{domain}.html", "w") as f:
        f.write("<html>")
        f.write("<head>")
        f.write(f"<title>Lepus Report for {domain}</title>")
        f.write("</head>")
        f.write("<body>")
        f.write(f"<h1>Lepus Report for {domain}</h1>")
        for key, value in findings.items():
            f.write(f"<h2>{key}</h2>")
            if isinstance(value, list):
                f.write("<ul>")
                for item in value:
                    f.write(f"<li>{item}</li>")
                f.write("</ul>")
            else:
                f.write(f"<p>{value}</p>")
        f.write("</body>")
        f.write("</html>")

    print(colored(f"  \__ HTML report saved to {domain}.html", "green"))
