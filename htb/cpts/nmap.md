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
```
sudo nmap -sn -oA [name] [IP] [IP] [IP]
```
## Host Port Scanning

## Saving the Results

## Service Enumeration

## Scripting Engine

## Performance Tuning
