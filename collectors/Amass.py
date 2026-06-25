import os
import subprocess
import tempfile
from termcolor import colored
from shutil import which

def init(domain):
    AM = []
    print(colored("[*]-Searching with Amass...", "yellow"))

    if not which("amass"):
        print(colored("  \__ Amass command not found in PATH. Skipping...", "red"))
        return []

    try:
        # Create a unique temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        # Run amass command and capture output
        # enum: enumeration mode
        # -passive: passive mode (fast)
        # -d: domain
        # -o: output to file
        # -silent: disable terminal output
        # -timeout: 2 minutes timeout to prevent hanging
        command = [
            "amass", "subs",
            "-names",
            "-d", domain,
            "-o", tmp_path,
        ]

        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=130)

        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                for line in f:
                    AM.append(line.strip().lower())
            os.remove(tmp_path) # Clean up temp file

        print(f"  \__ {colored('Subdomains found', 'cyan')}: {colored(len(set(AM)), 'yellow')}")
    except Exception as e:
        print(colored(f"  \__ Error running Amass: {e}", "red"))
    return list(set(AM))
