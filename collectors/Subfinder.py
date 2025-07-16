import os
from termcolor import colored

def init(domain):
    SF = []
    print(colored("[*]-Searching with Subfinder...", "yellow"))
    try:
        # Run subfinder command and capture output
        # -d: domain
        # -silent: no verbose output
        # -o: output to stdout
        command = f"subfinder -d {domain} -silent -o /tmp/subfinder_output.txt > /dev/null 2>&1"
        os.system(command)

        with open("/tmp/subfinder_output.txt", "r") as f:
            for line in f:
                SF.append(line.strip())

        os.remove("/tmp/subfinder_output.txt") # Clean up temp file
        print(f"  \__ {colored('Subdomains found', 'cyan')}: {colored(len(set(SF)), 'yellow')}")
    except Exception as e:
        print(colored(f"  \__ Error running Subfinder: {e}", "red"))
    return list(set(SF))
