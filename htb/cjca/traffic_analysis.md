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

# Wireshark

# Interesting filters. (To be placed later, these are just ones I happen to come across in the course.
## Capture Filters
## Display Filters
`ftp-data`
`http.request.method == "GET"`
`http.request.method == "POST"`
# Todo

