# Version 3.4.0

### --- New Features
1. Added Markov submodule
2. Added RIPE database lookup for CIDRs to be used in reverse lookup
3. Added --flush flag to purge an entry from the database and exit
4. Signature for kayako takeover
5. Signature for ning takeover
6. Signature for moosend takeover
7. Added export functionality when ctrl+c is pressed up to the latest completed module - does not create diff.
8. New Project Discovery Chaos collector
9. New ZoomEye collector
10. New ThreatMiner collector
11. New FOFA collector

### --- Bug Fixes
1. Fixed bugs in Censys collector so that search result limit is identified and identification is better
2. Fixed logical bug in portscan that caused very long duration of execution
3. Removed Entrust Certificates collector as it's no longer being used
4. Better exception handling in some minor cases
5. Fixed a bug in CertSpotter collector's result identification
6. Fixed a bug in DNSTrails collector's result identification
7. Fixed a bug in GoogleTransparency collector's response parsing
8. Fixed logic bugs in Shodan collector
9. Fixed a bug in ProjectCrobat collector

### --- Misc
1. Changed database name from findings.sqlite to lepusdb.sqlite
2. Minor cosmetic fixes in output
3. Updated user-agent strings
4. Changed README file
5. Updated requirements.txt

# Version 3.3.2

### --- New Features
1. Added Project Crobat collector
2. Added export of wildcards

### --- Bug Fixes
1. Fixed a bug on the CRT collector
2. Fixed a bug that was unintentionally purging the retrieved DNS records of the target domain

### --- Misc
1. Updated requirements.txt
2. Updated Spyse collector
3. Removed broken Entrust Certificates collector

# Version 3.3.1

### --- New Features
1. Added history on diff log

### --- Bug Fixes
1. Fixed a bug on the Slack messaging mechanism

### --- Misc
1. Updated requirements.txt

# Version 3.3.0

### --- New Features
1. Added various new signatures for takeover identification
2. Added the ability to have more than one signature per service 
3. Added new permutation function for numeric iteration

### --- Bug Fixes
1. Fixed the Spyse collector so that it's working due to changes in the API

### --- Misc
1. Changed handling of permutations so now they happen in chunks
2. Changed handling of wildcard identification to use chunks
3. Memory handling is a lot better
4. Updated README.md

# Version 3.2.2

### --- New Features
1. Display location information on networks identified by the RDAP submodule
2. Diff between runs against the same domain

### --- Misc
1. Various enhancements on export functionality
2. Updated README.md
3. Updated requirements.txt

# Version 3.2.1

### --- New Features
1. Slack notifications on new potential takeovers
2. Export of findings

### --- Bug Fixes
1. Fixed a logic bug on the handling of old findings

### --- Misc
1. Database improvements
2. Removed DNSDB collector
3. Updated README.md
4. Updated requirements.txt

# Version 3.2.0

### --- New Features
1. SQLite integration
2. IPv6 support
3. Memory management improvements
4. Spyse API collector

### --- Bug Fixes
1. Fixed an issue on the wildcard identification logic
2. Fixed a logic bug on the CertSpotter collector

### --- Misc
1. Updated README.md
2. Updated requirements.txt
3. Updated .gitignore
4. Added new takeover signatures
5. Added various records to the words.txt list used for permutations
6. Removed FindSubdomains collector

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
1. Updated README.md for Portscan and Takeover
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
