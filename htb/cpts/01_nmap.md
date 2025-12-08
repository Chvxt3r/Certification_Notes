# Host Enumeration
## Host Discovery
> Pipe to grep to display a list of responding hosts.  
> ` [nmap command] | grep for | cut -d" " -f5`  
### Scanning a network range
```
sudo nmap [network/cidr] -sn -oA [name]
```
`-sn` - Disables port scanning
`-oA` Stores results in all formats starting with [name]
### Scanning an IP List
```
sudo nmap -sn -oA [name] -iL [list].lst
```
`-iL` tells nmap to use the list for scan targets
### Scan Multiple IPs
**Scan multiple IPs**
```
sudo nmap -sn -oA [name] [IP] [IP] [IP]
```
**Scan a range of IPs**
```
sudo nmap -sn -oA [name] 10.10.10.5-25
```
### Scan a single IP
If `-sn` is specified, Nmap will automatically use pings `-PE` to determine if this host is up. Otherwise it uses ARP.  
We can determine how Nmap decided the host was reponding by using the `--reason` flag.  
We can also disable `ARP` by using the `--disable-arp-ping` flag.  

## Host Port Scanning
### 6 Different States we can obtain for a scanned port
|State|Description|
|-----|-----------|
|`open`|This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations.|
|`closed`|When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an `RST` flag. This scanning method can also be used to determine if our target is alive or not.|
|`filtered`|Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.|
|`unfiltered`|This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.|
|`open`|filtered|If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port.|
|`closed`|filtered|This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.|
### TCP Port Discovery
**Scanning Top 10 TCP Ports**
```
**Tracing the packets**
```
sudo nmap [ip] -p [port] --packet-trace -Pn -n --disable-arp-ping
sudo nmap [IP] --top-ports=10
```
'-p [port]` - Only scans the specified port
`--packet-trace` - Shows all packets sent/received
`-n` - Disables DNS resolution

### Packet Tracing Interpretation
```
### Analyzing Responses
**Example Response**
```
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 15:39 CEST
SENT (0.0429s) TCP 10.10.14.2:63090 > 10.129.2.28:21 S ttl=56 id=57322 iplen=44  seq=1699105818 win=1024 <mss 1460>
RCVD (0.0573s) TCP 10.129.2.28:21 > 10.10.14.2:63090 RA ttl=64 id=0 iplen=40  seq=0 win=0
Nmap scan report for 10.129.2.28
Host is up (0.014s latency).

PORT   STATE  SERVICE
21/tcp closed ftp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

**Interpreting the request**
|Message|Description|
|-------|-----------|
|`SENT (0.0429s)`|Indicates the SENT operation of Nmap, which sends a packet to the target.|
|`TCP`|Shows the protocol that is being used to interact with the target port.|
|`10.10.14.2:63090 >`|Represents our IPv4 address and the source port, which will be used by Nmap to send the packets.|
|`10.129.2.28:21`|Shows the target IPv4 address and the target port.|
|`S`|SYN flag of the sent TCP packet.|
|`ttl=56 id=57322 iplen=44 seq=1699105818 win=1024 mss 1460`|Additional TCP Header parameters.|

**Interpreting the response**
|Message|Description|
|-------|-----------|
|`RCVD (0.0573s)`|Indicates a received packet from the target.|
|`TCP`|Shows the protocol that is being used.|
|`10.129.2.28:21 >`|Represents targets IPv4 address and the source port, which will be used to reply.|
|`10.10.14.2:63090`|Shows our IPv4 address and the port that will be replied to.|
|`RA`|RST and ACK flags of the sent TCP packet.|
|`ttl=64 id=0 iplen=40 seq=0 win=0`|Additional TCP Header parameters.|

**Connect Scan** - `-sT`  
Attempts to connect to the port. The port is considered open if the target port responds with a `SYN-ACK` and closed if it respondes with a `RST`  
> The connect scan is not stealthy. These connections maybe logged and flagged by SIEM.   

**Filtered Ports**  
Ports show as filtered for several reasons. They can either be `dropped` or `rejected`. We can use `--packet-trace` to determine which.  
`dropped` - Nmap received no response from the target(--max-retries=10). If still no response, port is marked filtered  
`rejected` - Firewall will responed with an ICMP type=3/code=3 rejection, indicating the port is unreachable  

### Open UDP Ports.
```
sudo nmap [IP] -F -sU
```
> No connection state to verify connection, so UDP is much slower. UDP only responds if the application is configured to respond.  

```
sudo nmap [IP] -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
```
We can rely on `--packet-trace` to tell us if the port is actually closed by the `ICMP` responde code (`error code 3`)

### Version Scanning
> `-sV`  
```
sudo nmap [IP] -Pn -n -sV --disable-arp-ping --packet-trace --reason
```

## Saving the Results
|Switch|Output|
|------|------|
|`-oN`|Normal Output with the `.nmap` extension|
|`-oG`|Grepable Output with `.gnmap` extension|
|`-oX`|XML output with the `.xml` extension|
|`-oA`|Outputs all 3|

### Converting to HTML
```
xsltproc target.xml -o target.html
```

## Service Enumeration
> `-sV`  
### Useful Options
- `--stats-every=5s` - Gives stats every 5 seconds. Can use `s` or `m`
- `-v`/`-vv` - Increase the verbosity level
### Banner Grabbing
> Nmap automatically tries to grab and display the banner. If it can't, it will try and identification through signatures.  

## Scripting Engine
### Categories
|Category|Description|
|--------|-----------|
|`auth`|Determination of authentication credentials.|
|`broadcast`|Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans.|
|`brute`|Executes scripts that try to log in to the respective service by brute-forcing with credentials.|
|`default`|Default scripts executed by using the `-sC` option.|
|`discovery`|Evaluation of accessible services.|
|`dos`|These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.|
|`exploit`|This category of scripts tries to exploit known vulnerabilities for the scanned port.|
|`external`|Scripts that use external services for further processing.|
|`fuzzer`|This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.|
|`intrusive`|Intrusive scripts that could negatively affect the target system.|
|`malware`|Checks if some malware infects the target system.|
|`safe`|Defensive scripts that do not perform intrusive and destructive access.|
|`version`|Extension for service detection.|
|`vuln`|Identification of specific vulnerabilities.|

### Default Scripts
Run with `-sC`

### Specific Scripts Category
```
sudo nmap [target] --script [category]
```

### Specifying Scripts
```
sudo nmap [target] --script [script name],[script name],...
```

### Vulnerability Assessment
```
sudo nmap [target] -p [port] -sV --script vuln
```

## Performance Tuning
### Timeouts
Default is 100ms
```
sudo nmap [target] --iniital-rtt-timeout 50ms --max-rtt-timeout 100ms
```

### Max Retries
- Default Value is 10
```
sudo nmap [target] --max-retries 0
```

### Rates
* Specifies the number of packets sent per second. Useful for white-box, but noisy otherwise.
```
sudo nmap [target] --min-rate 300
```

### Timing
* Useful for black-box, where we are trying to be surreptitious. Determines how aggressive the scan is.
|Setting|Description|
|-------|-----------|
|`-T 0`|paranoid|
|`-T 1`|sneaky|
|`-T 2`|polite|
|`-T 3`|normal|
|`-T 4`|aggressive|
|`-T 5`|insane|

## Firewall and IDS/IPS Evasion

# Todo
- [ ] Resume at Nmap scripting engine/Default Scripts.
