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

### dig - Domain Information Groper
|Command|Description|
|-------|-----------|
|`dig domain.com`|Performs a default A record lookup for the domain.|
|`dig domain.com A`|Retrieves the IPv4 address (A record) associated with the domain.|
|`dig domain.com AAAA`|Retrieves the IPv6 address (AAAA record) associated with the domain.|
|`dig domain.com MX`|Finds the mail servers (MX records) responsible for the domain.|
|`dig domain.com NS`|Identifies the authoritative name servers for the domain.|
|`dig domain.com TXT`|Retrieves any TXT records associated with the domain.|
|`dig domain.com CNAME`|Retrieves the canonical name (CNAME) record for the domain.|
|`dig domain.com SOA`|Retrieves the start of authority (SOA) record for the domain.|
|`dig @1.1.1.1 domain.com`|Specifies a specific name server to query; in this case 1.1.1.1|
|`dig +trace domain.com`|Shows the full path of DNS resolution.|
|`dig -x 192.168.1.1`|Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.|
|`dig +short domain.com`|Provides a short, concise answer to the query.|
|`dig +noall +answer domain.com`|Displays only the answer section of the query output.|
|`dig domain.com ANY`|Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482).|

### Groping DNS (giggity)
```
Chvxt3r@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

## Subdomain Bruteforce
### DNSEnum
```
dnsenum --enum [target] -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```
## DNS Zone Transfer
> Zone Transfers may be disabled. It would be a misconfiguration to allow zone transfers
```
dig axfr @[dns server] [domain]
```

## Virtual Hosts
> Virtual hosts are a function of a webserver, not to be confused with subdomains, which are a function of DNS. They may or may not resolve to a subdomain.

### GoBuster
```
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

## Certificate Transparency Logs
> Public, append-only ledgers that record the issuance of SSL/TLS certificates

### [crt.sh](https://crt.sh/)
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
The above command get's all the domains of facebook.com that contain 'dev'
- `curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain facebook.com.
- `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the name_value field (which contains the domain or subdomain) includes the string "dev". The -r flag tells jq to output raw strings.
- `sort -u`: This sorts the results alphabetically and removes duplicates.

# Fingerprinting
## Purpose
- Targeted Attacks
- Identifying misconfigurations
- Prioritizing targets
- Building a comprehensive profile

## Techniques
- Banning Grabbing
- Analyzing headers
- Probing for unique responses
- Analyzing page content

### Banner Grabbing
Using Curl
```
curl -I [domain]
```
> Don't forget to grab the banners of any redirects  

### Fingerprinting Web Application Firewalls
Using wafw00f
```
wafw00f [domain]
```
### Fingerprinting using Nikto
```
nikto -h [domain] -Tuning b
```

# Crawling
## Crawling
## Robots.txt
### Example
```
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```
The above contains the following directives:
- All user agents are disallowed from accessing the /admin/ and /private/ directories.
- All user agents are allowed to access the /public/ directory.
- The Googlebot (Google's web crawler) is specifically instructed to wait 10 seconds between requests.
- The sitemap, located at https://www.example.com/sitemap.xml, is provided for easier crawling and indexing.

## Well-Known URLS
> The `/.well-known/` directory contains a centralized repository of a website metadata.  
|URI Suffix|Description|Status|Reference|
|----------|-----------|------|---------|
|`security.txt`|Contains contact information for security researchers to report vulnerabilities.|Permanent|RFC 9116|
|`/.well-known/change-password`|Provides a standard URL for directing users to a password change page.|Permanent|https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri|
|`openid-configuration`|Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol.|Permanent|http://openid.net/specs/openid-connect-discovery-1_0.html|
|`assetlinks.json`|Used for verifying ownership of digital assets (e.g., apps) associated with a domain.|Permanent|https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md|
|`mta-sts.txt`|Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.|Permanent|RFC 8461|

# Search Engine Discovery

# Web Archives

# Automated Recon

# TODO
- [x] Done
