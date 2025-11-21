# Summary
`Network Traffic Analysis (NTA)` can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.

# Analysis
## Summary
Traffic Analysis is a `detailed examination of an event or process`, determining its origin and impact, which can be used to trigger specific precautions and/or actions to support or prevent future occurrences. With network traffic, this means breaking down the data into understandable chunks, examining it for anything that deviates from regular network traffic, for potentially malicious traffic such as unauthorized remote communications from the internet over RDP, SSH, or Telnet, or unique instances preceding network issues. While performing our analysis, we are also looking to see what the trends look like within the traffic and determine if it matches a baseline of typical operational traffic.
## Dependencies
|Dependency|Passive|Active|Description|
|----------|-------|------|-----------|
|`Permission`|`[x]`|`[x]`|Depending on the organization we are working in, capturing data can be against policy or even against the law in some sensitive areas like healthcare or banking. Be sure always to obtain permission in writing from someone with the proper authority to grant it to you. We may style ourselves as hackers, but we want to stay in the light legally and ethically.|
|`Mirrored Port`|`[x]`|`[ ]`|A switch or router network interface configured to copy data from other sources to that specific interface, along with the capability to place your NIC into promiscuous mode. Having packets copied to our port allows us to inspect any traffic destined to the other links we could normally not have visibility over. Since VLANs and switch ports will not forward traffic outside of their broadcast domain, we have to be connected to the segment or have that traffic copied to our specific port. When dealing with wireless, passive can be a bit more complicated. We must be connected to the SSID we wish to capture traffic off of. Just passively listening to the airwaves around us will present us with many SSID broadcast advertisements, but not much else.|
|`Capture Tool`|`[x]`|`[x]`|A way to ingest the traffic. A computer with access to tools like TCPDump, Wireshark, Netminer, or others is sufficient. Keep in mind that when dealing with PCAP data, these files can get pretty large quickly. Each time we apply a filter to it in tools like Wireshark, it causes the application to parse that data again. This can be a resource-intensive process, so make sure the host has abundant resources.|
|`In-line Placement`|`[ ]`|`[x]`|Placing a Tap in-line requires a topology change for the network you are working in. The source and destination hosts will not notice a difference in the traffic, but for the sake of routing and switching, it will be an invisible next hop the traffic passes through on its way to the destination.|
|`Network Tap or Host With Multiple NIC's`|`[ ]`|`[x]`|A computer with two NIC's, or a device such as a Network Tap is required to allow the data we are inspecting to flow still. Think of it as adding another router in the middle of a link. To actively capture the traffic, we will be duplicating data directly from the sources. The best placement for a tap is in a layer three link between switched segments. It allows for the capture of any traffic routing outside of the local network. A switched port or VLAN segmentation does not filter our view here.|
|`Storage and Processing Power`|`[x]`|`[x]`|You will need plenty of storage space and processing power for traffic capture off a tap. Much more traffic is traversing a layer three link than just inside a switched LAN. Think of it like this; When we passively capture traffic inside a LAN, it's like pouring water into a cup from a water fountain. It's a steady stream but manageable. Actively grabbing traffic from a routed link is more like using a water hose to fill up a teacup. There is a lot more pressure behind the flow, and it can be a lot for the host to process and store.|
## In Practice
### Descriptive Analysis
1. Define the issue
    - Breach, Networking issue, etc.
2. Define the scope and the goal
    - Target
    - When?
    - Supporting info
3. Define targets (net/host(s)/protocol)
### Diagnostic Analysis
4. Capture Network Traffic
5. Identification of required network traffic components (filtering)
6. Understand the capture
### Predictive Analysis
7. Note taking of found results
8. Summary of the analysis (reporting)

### Prescriptive Analysis
**Summary:** Prescriptive analysis aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process.  
The process is the same as in the descriptive analysis, we're just trying to influence a decision with our report, rather than solve a problem.

### Key Components
- Know the environment
- Placement of the packet capturing host
- Persistence (This is a lot of data and what your looking for may not be obvious)

### Easy Wins
- Standard Protocols first, then the austere and specific
- Look for Patterns (Is a host checking in with something on the daily?)
- Look for Host to Host communication. (There's no reason in a well-built network client machines should talk to each other)
- Unique events (Why is a host reaching out to a server on the internet via smb? Why is it's user-agent string different than anything we use?)

# Tcpdump
## Summary
Command-line Packet Sniffer for directly capture packets and interpreting data frames.

**Requires root permissions**
### Installation
```
sudo apt install tcpdump
```
### Validation
```
which tcpdump
sudo tcpdump --version
```
## Capturing Traffic
### Basic Capture Options
|switch|Result|
|------|------|
|`D`|Will display any interfaces available to capture from.|
|`i`|Selects an interface to capture from. ex. -i eth0|
|`n`|Do not convert addresses (i.e., host addresses, port numbers, etc.) to names.|
|`e`|Will grab the ethernet header along with upper-layer data.|
|`X`|Show Contents of packets in hex and ASCII.|
|`XX`|Same as X, but will also specify ethernet headers. (like using Xe)|
|`v, vv, vvv`|Increase the verbosity of output shown and saved.|
|`c`|Grab a specific number of packets, then quit the program.|
|`s`|Defines how much of a packet to grab.|
|`S`|change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101)|
|`q`|Print less protocol information.|
|`r file.pcap`|Read from a file.|
|`w file.pcap`|Write into a file|
**Switch Combinations** - Best practice is to chain them together under a single `-`. Ex: `sudo tcpdump -i eth0 --nnvXX`

### Helpful Capture Filters
|Filter|Result|
|------|------|
|`host`|filter visible traffic to show anything involving the designated host. Bi-directional|
|`src / dest`|`src` and `dest` are modifiers. We can use them to designate a source or destination host or port.|
|`net`|`net` will show us any traffic sourcing from or destined to the network designated. It uses CIDR notation.|
|`proto`|will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)|
|`port`|`port` is bi-directional. It will show any traffic with the specified port as the source or destination.|
|`portrange`|`portrange` allows us to specify a range of ports. (0-1024)|
|`less / greater "< >"`|`less` and `greater` can be used to look for a packet or protocol option of a specific size.|
|`and / &&`|`and` `&&` can be used to concatenate two different filters together. for example, src host AND port.|
|`or`|`or` allows for a match on either of two conditions. It does not have to meet both. It can be tricky.|
|`not`|`not` is a modifier saying anything but x. For example, not UDP.|

**Syntax Examples**
```
# Host
## Syntax: host [IP]
sudo tcpdump -i eth0 host 172.16.146.2

# Source/Destination Filter
## Syntax: src/dst [host|net|port] [IP|Network Range|Port]
sudo tcpdump -i eth0 src host 172.16.146.2

# Using Source with Port as a filter
sudo tcpdump -i eth0 tcp src port 80

# Destination in combination with Net
sudo tcpdump -i eth0 dest net 172.16.146.0/24

# Protocol Filter with common name
## Syntax: [tcp/udp/icmp]
sudo tcpdump -i eth0 udp

# Protocol Filter with port number
sudo tcpdump -i eth0 proto 17

# Port Filter
## Syntax: port [port number]
sudo tcpdump -i eth0 tcp port 443

# Port Range Filter
## Syntax: portrange [portrange 0-65535]
sudo tcpdump -i eth0 portrange 0-1024

# Lesser/Greater Filter
## Syntax: less/greater [size in bytes]
sudo tcpdump -i eth0 less 64

# AND Filter
## Syntax: and [requirement]
sudo tcpdump -i eth0 host 192.168.0.1 and port 23

# OR Filter
## Syntax: or/|| [requirement]
sudo tcpdump -r sus.pcap icmp or host 172.16.146.1

# NOT Filter
## Syntax: not/! [requirement]
sudo tcpdump -r sus.pcap not icmp
```
**Reminder** - If specifying port 80, it will capture all traffic on port 80 (TCP, UDP, ICMP). Remember to specify the transport protocol in your filter.
### Tips and Tricks
Using the `-S` switch will display absolute sequence numbers, which can be extremely long. Typically, tcpdump displays relative sequence numbers, which are easier to track and read. However, if we look for these values in another tool or log, we will only find the packet based on absolute sequence numbers. For example, 13245768092588 to 100.

The `-v`, `-X`, and `-e` switches can help you increase the amount of data captured, while the `-c`, `-n`, `-s`, `-S`, and `-q` switches can help reduce and modify the amount of data written and seen.

Many handy options that can be used but are not always directly valuable for everyone are the `-A` and `-l` switches. A will show only the ASCII text after the packet line, instead of both ASCII and Hex. `L` will tell tcpdump to output packets in a different mode. `L` will line buffer instead of pooling and pushing in chunks. It allows us to send the output directly to another tool such as grep using a pipe |.

**Piping to Grep**
```
sudo tcpdump -Ar http.cap -l | grep 'mailto:*'
```
**Looking for TCP Protocol Flags**
```
tcpdump -i eth0 'tcp[13] &2 != 0'
```

# Wireshark
## Summary
Wireshark is a free and open-source network traffic analyzer much like tcpdump but with a graphical interface.

## Capturing Traffic
### Capture Filters
|Capture Filter|Result|
|--------------|------|
|host x.x.x.x|Capture only traffic pertaining to a certain host|
|net x.x.x.x/24|Capture traffic to or from a specific network (using slash notation to specify the mask)|
|src/dst net x.x.x.x/24|Using src or dst net will only capture traffic sourcing from the specified network or destined to the target network|
|port #|will filter out all traffic except the port you specify|
|not port #|will capture everything except the port specified|
|port # and #|AND will concatenate your specified ports|
|portrange x-x|portrange will grab traffic from all ports within the range only|
|ip / ether / tcp|These filters will only grab traffic from specified protocol headers.|
|broadcast / multicast / unicast|Grabs a specific type of traffic. one to one, one to many, or one to all.|

### Display Filters
|Display Filters|Result|
|---------------|------|
|ip.addr == x.x.x.x|Capture only traffic pertaining to a certain host. This is an OR statement.|
|ip.addr == x.x.x.x/24|Capture traffic pertaining to a specific network. This is an OR statement.|
|ip.src/dst == x.x.x.x|Capture traffic to or from a specific host|
|dns / tcp / ftp / arp / ip|filter traffic by a specific protocol. There are many more options.|
|tcp.port == x|filter by a specific tcp port.|
|tcp.port / udp.port != x|will capture everything except the port specified|
|and / or / not|AND will concatenate, OR will find either of two options, NOT will exclude your input option.|
> Keep in mind, while utilizing Display filters traffic is processed to show only what is requested but the rest of the capture file will not be overwritten. Applying Display filters and analysis options will cause Wireshark to reprocess the pcap data in order to apply.

## Advanced Usage
### Follow a TCP Stream
- right-click on a packet from the stream we wish to recreate.
- select follow → TCP
- this will open a new window with the stream stitched back together. From here, we can see the entire conversation.
- Alternatively, you can use the filter `tcp.stream eq #` to find and track a conversation
### Extracting Data and File from a capture
- Stop the capture
- Select the File radial → Export → , then select the protocol format to extract from.
- (DICOM, HTTP, SMB, etc.)
### FTP Extraction
- `ftp` will display anything about the FTP Protocol
- `ftp.request.command` will show any commands sent across the control channel. Useful for `usernames` and `passwords`.
- `ftp-data` will show any data sent over the data channel.
    * We can use this to caputre anything sent during the conversation. We can reconstruct anything transferred by placing the raw data back in to a new file and naming it appropriately
- Step-by-step
    * Identify any FTP traffic using the `ftp` display filter.
    * Look at the command controls sent between the server and hosts to determine if anything was transferred and who did so with the `ftp.request.command` filter.
    * Choose a file, then filter for `ftp-data`. Select a packet that corresponds with our file of interest and follow the TCP stream that correlates to it.
    * Once done, Change "Show and save data as" to "Raw" and save the content as the original file name.
    * Validate the extraction by checking the file type.
### Decrypting RDP Connections
> Note: you won't see alot of traffic until you interecept the TLS Key.
- Check for RDP connections in the traffic
    * Display Filter `tcp.port == 3389`
- Extract the server certificate from the tcp stream
    * Locate the certificate tcp stream
    * follow stream
    * export certificate (file -> export objects -> X509AF)
- Extract the private key from the certificate
    * ``` openssl x509 -in [server cert file] -pubkey ```
    * `REQUIRES FURTHER RESEACH`
- Import the RDP Key
    * Edit -> Preferences -> Protocols -> TLS
    * Edit RSA Keys list
    * Click the + to add a key
    * Type in the IP address of the RDP server
    * Type in the port used
    * Protocol filed equals `tpkt` or `blank`
    * Browse to the server key file and add it in the key file section
    * save and refresh the pcap file.

# Interesting filters. (To be placed later, these are just ones I happen to come across in the course.
## Capture Filters
## Display Filters
`ftp-data`
`http.request.method == "GET"`
`http.request.method == "POST"`
# Todo
- [ ] Research how to pull the RSA Private key from the TLS certificate for wireshark

