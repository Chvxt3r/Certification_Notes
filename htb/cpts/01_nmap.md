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
# Example Response
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

## Saving the Results

## Service Enumeration

## Scripting Engine

## Performance Tuning
