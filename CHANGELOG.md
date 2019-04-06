# Version 3.1.0

### --- New Features
1. Added Takeover module
2. Implemented chunking in places were it wasn't present but might be needed
3. Progress bars now appear on the same line as different chunks are processed
4. Added ports 9943 and 9980 in the "huge" preset for the portscan module

### --- Bug Fixes
1. Fix in Censys collector regarding pagination and false positives
2. Fix in DNSDB collector - error handling to account for cloudflare changes
3. Fix in Riddler collector - error handling when 500 internal server error occurs
4. Fix in DNSTrails collector - error handling when api search limit has been exceeded
5. Fix in CRT collector - account for 504 server response when the query times out
6. Fix a bug during wildcard identification that didn't allow for threads to finish properly

### --- Misc
1. Updated readme for Portscan and Takeover
2. Updated requirements.txt to account for new cloudflare bypass
3. Portscan module - slight change due to my OCDs
4. Updated wordlists
5. Added generic exception handling on all collectors in case something odd happens

# Version 3.0.2

### --- New Features
1. Added Project Sonar collector
2. Re-implemented DNSDB collector with CF Anti-DDOS bypass
3. URLs generated from the Port Scan module are now also printed on the console

### --- Bug Fixes
1. Fixed a bug on Port Scan module where URLs were not generated correctly

### --- Misc
1. Updated requirements.txt
2. Updated README.md

# Version 3.0.1

### --- New Features
1. Support for Python 3

### --- Bug Fixes
1. Exception handling on CRT.sh collector

### --- Misc
1. Added BSD-3 Clause LICENSE
2. Added CHANGELOG.md
3. Updated README.md
4. Updated requirements.txt
5. Removed DNSDB collector
6. Removed DNSDumpster collector

# Version 2.3.7

### --- New Features
1. Historic diff logs

### --- Bug Fixes
1. Double allocations in permutations

### --- Misc
1. Minor tweak on permutations
2. Updated requirements.txt
3. New subdomain wordlist

# Version 2.3.6

### --- New Features
1. Replaced ASN and WHOIS modules with a single module that performs RDAP lookups

### --- Misc
1. Added diff checks on wildcard identification
2. Moved diff check with old findings before the execution of RDAP module
3. Changed some output in order to be consistent across all modules
4. Updated README.md

# Version 2.3.5

### --- Bug Fixes
1. Improved exception handling for Riddler collector
2. Redesigned the wildcard identification to catch true negatives that were missed

### --- Misc
1. Added .gitignore

# Version 2.3.4

### --- Bug Fixes
1. Improved exception handling
2. Fixed a bug on argument validity checks
3. Fixed a bug on wildcard identification

### --- Misc
1. Updated requirements.txt
2. Updated README.md

# Version 2.3.3

### --- New Features
1. Added zone transfer capability
2. Added reverse lookups on IP ranges (-r, --ranges)
3. Added validity checks on provided arguments
4. Added chunk support on reverse lookups
5. Added chunk support on port scan

### --- Bug Fixes
1. Fixed a bug on wildcard checks
2. Fixed a bug on diff checks with old results

### --- Misc
1. Utilities code redesign
2. Updated README.md

# Version 2.2.5

### --- New Features
1. Entrust Certificates collector
2. CertSpotter collector
3. SSL identification on portscan & url generation
4. Reverse DNS submodule
5. Diff on resolved domains from previous run

### --- Bug Fixes
1. Rewrite of the wildcard identification mechanism
2. Exception handling on Censys collector
3. Convert to lowercase and unique after final list is merged
4. ASN and WHOIS checks are only performed on public resolved IPs

### --- Misc
1. Updated requirements.txt
2. Updated README.md
3. Removed --show-wildcards option
4. Small additions to permutation wordlist
5. Added top ~100k subdomains list under lists/
6. Added functionality to save results from collectors
7. Now saving project folders under results/
8. Showing total parts while progress-bar is loading
