# Intro

# Whois
## Command
```
whois [domain]
```
## What's interesting
- Key Personnel - May reveal who's responsible for the domain and their email address
- Network Infrastructure - Name Servers and IP's may provide insight in to the targets infrastructure
- Historical Analysis - Historical whois ([WhoisFreaks](https://whoisfreaks.com)) can reveal changes in ownership, contact info, or technical details over time.

# DNS & Subdomains
## DNS
## Digging DNS
### Common Tools
|Tool|Key Features|Use Cases|
|----|------------|---------|
|`dig`|Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output.|Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.|
|`nslookup`|Simpler DNS lookup tool, primarily for A, AAAA, and MX records.|Basic DNS queries, quick checks of domain resolution and mail server records.|
|`host`|Streamlined DNS lookup tool with concise output.|Quick checks of A, AAAA, and MX records.|
|`dnsenum`|Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).|Discovering subdomains and gathering DNS information efficiently.|
|`fierce`|DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.|User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.|
|`dnsrecon`|Combines multiple DNS reconnaissance techniques and supports various output formats.|Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.|
|`theHarvester`|OSINT tool that gathers information from various sources, including DNS records (email addresses).|Collecting email addresses, employee information, and other data associated with a domain from multiple sources.|
|`Online DNS Lookup Services`|User-friendly interfaces for performing DNS lookups.|Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information|

## Subdomain Bruteforce
## DNS Zone Transfer
## Virtual Hosts
## Certificate Transparency Logs

# Fingerprinting

# Crawling
## Crawling
## Robots.txt
## Well-Known URLS

# Search Engine Discovery

# Web Archives

# Automated Recon
