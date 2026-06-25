import os
import subprocess
import tempfile
from termcolor import colored
from shutil import which

def init(domain):
    SF = []
    print(colored("[*]-Searching with Subfinder...", "yellow"))

    if not which("subfinder"):
        print(colored("  \__ Subfinder command not found in PATH. Skipping...", "red"))
        return []

    try:
        # Create a unique temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        # Run subfinder command and capture output
        # -d: domain
        # -silent: no verbose output
        # -o: output to file
        command = ["subfinder", "-d", domain, "-silent", "-o", tmp_path]

        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)

        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                for line in f:
                    SF.append(line.strip().lower())
            os.remove(tmp_path) # Clean up temp file

        print(f"  \__ {colored('Subdomains found', 'cyan')}: {colored(len(set(SF)), 'yellow')}")
    except Exception as e:
        print(colored(f"  \__ Error running Subfinder: {e}", "red"))
    return list(set(SF))
