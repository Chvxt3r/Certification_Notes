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

## Saving the Results

## Service Enumeration

## Scripting Engine

## Performance Tuning
