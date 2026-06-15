# Attacking Enterprise Networks Methodology

## External Enumeration

* Quick Scan
```bash
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope
```
* Aggressive Scan
```bash
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope
```
* Pull out the running services
```bash
grep -v "^#|Status: Up" inlanefreight_ept_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr
```
* DNS Zone Transfer
```bash
dig axfr @10.129.229.147 inlanefreight.local
```
* Fuzz for additional hosts
```bash
# Find the content length of a known not valid to filter with
curl -s -I http://10.129.203.101 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
# FFUF for additional valid subdomains
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://10.129.229.147/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157
```
* Add all discovered hosts to /etc/hosts

## Low Hanging Fruit
* Exploit the FTP anon login

## Web Enum & Exploitation
* Eyewitness to enumerate a large number of subdomains
```bash
eyewitness -f ilfreight_subdomains -d ilfreight_subdomain_eyewitness
```

