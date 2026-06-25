import os
import subprocess
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import utilities.DatabaseHelpers

def brute_force_subdomain(subdomain, wordlist_path, domain):
    output_file = f"findings/{domain}/ffuf_results_{subdomain.replace('.', '_')}.json"
    
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Using ffuf for directory brute-forcing
        # -w: wordlist
        # -u: URL with FUZZ keyword
        # -mc: match status codes
        # -o: output file
        # -of: output format
        # -s: silent mode
        command = [
            "ffuf", "-w", wordlist_path, 
            "-u", f"http://{subdomain}/FUZZ", 
            "-mc", "200,301,302", 
            "-o", output_file, 
            "-of", "json",
            "-s"
        ]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        return subdomain, output_file, True
    except Exception as e:
        return subdomain, None, False

def init(db, domain):
    print(colored("\n[*]-Performing directory and file brute-forcing...", "yellow"))

    # Get all resolved subdomains from the database
    resolved_subdomains = []
    try:
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    if not resolved_subdomains:
        print(colored("  \__ No resolved subdomains found for brute-forcing.", "yellow"))
        return

    # Define a common wordlist
    wordlist_path = "/usr/share/dirb/wordlists/common.txt" 

    if not os.path.exists(wordlist_path):
        # Check alternative common location
        alt_path = "/usr/share/wordlists/dirb/common.txt"
        if os.path.exists(alt_path):
            wordlist_path = alt_path
        else:
            print(colored(f"  \__ Wordlist not found at {wordlist_path}. Skipping directory brute-force.", "red"))
            return

    print(colored(f"  \__ Brute-forcing {len(resolved_subdomains)} subdomains in parallel...", "cyan"))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(brute_force_subdomain, sub, wordlist_path, domain): sub for sub in resolved_subdomains}
        
        for future in as_completed(futures):
            subdomain, output_file, success = future.result()
            if success:
                print(colored(f"    \__ Finished {subdomain}. Results in {output_file}", "green"))
            else:
                print(colored(f"    \__ Failed brute-forcing {subdomain}", "red"))
