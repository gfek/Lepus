import os
from termcolor import colored
import utilities.DatabaseHelpers

def init(db, domain):
    print(colored("\n[*]-Performing directory and file brute-forcing...", "yellow"))

    # Get all resolved subdomains from the database
    resolved_subdomains = []
    try:
        resolved_subdomains = utilities.DatabaseHelpers.getResolvedSubdomains(db, domain)
    except Exception as e:
        print(colored(f"  \__ Error retrieving resolved subdomains: {e}", "red"))
        return

    # Define a common wordlist (user should have SecLists or similar)
    # For demonstration, we'll assume a generic path. User needs to provide a real one.
    wordlist_path = "/usr/share/dirb/wordlists/common.txt" # Example path, user should adjust

    if not os.path.exists(wordlist_path):
        print(colored(f"  \__ Wordlist not found at {wordlist_path}. Please provide a valid path to a directory brute-forcing wordlist (e.g., from SecLists).", "red"))
        return

    for subdomain in resolved_subdomains:
        print(colored(f"  \__ Brute-forcing {subdomain}...", "cyan"))
        output_file = f"findings/{domain}/ffuf_results_{subdomain.replace('.', '_')}.json"

        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file)
        os.makedirs(output_dir, exist_ok=True)

        try:
            # Using ffuf for directory brute-forcing
            # -w: wordlist
            # -u: URL with FUZZ keyword
            # -mc: match status codes (200, 301, 302 are common for valid content)
            # -o: output file
            # -of: output format (json)
            command = f"ffuf -w {wordlist_path} -u http://{subdomain}/FUZZ -mc 200,301,302 -o {output_file} -of json > /dev/null 2>&1"
            os.system(command)
            print(colored(f"    \__ Results saved to {output_file}", "green"))
        except Exception as e:
            print(colored(f"    \__ Error running ffuf on {subdomain}: {e}", "red"))
