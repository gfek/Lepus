import os
from termcolor import colored

def init(domain):
    AM = []
    print(colored("[*]-Searching with Amass...", "yellow"))
    try:
        # Run amass command and capture output
        # enum: enumeration mode
        # -d: domain
        # -o: output to stdout
        command = f"amass enum -d {domain} -o /tmp/amass_output.txt > /dev/null 2>&1"
        os.system(command)

        with open("/tmp/amass_output.txt", "r") as f:
            for line in f:
                AM.append(line.strip())

        os.remove("/tmp/amass_output.txt") # Clean up temp file
        print(f"  \__ {colored('Subdomains found', 'cyan')}: {colored(len(set(AM)), 'yellow')}")
    except Exception as e:
        print(colored(f"  \__ Error running Amass: {e}", "red"))
    return list(set(AM))
