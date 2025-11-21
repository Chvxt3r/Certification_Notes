# Definitions and Scope
## Definitions
- An`event` occurs in a system or network. Can be user controlled or automated
    * A user sending an emial
    * A mouse click
    * A Firewall allowing a connection
- An `incident` is an event with negative consequences.
    * System crash
    * Unauthorized access to sensitive data
    * Natural disassters
    - More specific definition of an `incident`, might be an event with a clear intent to cause harm performed against an organizations systems.
        * Data Theft
        * Funds Theft
        * Unauthorized access to data
        * Installation of malware and `RATs`
- `Incident Handling` is a clearly defined set of procedures for managing and responding to security incidents in a computer or network environment.
- Incident Handling lifecycle
![Incident Handling Lifecycle](../images/ir-lifecycle.png)
## Resources
- [NIST's Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- Example Incident Specific Reports
    * [Confluence Labs Leads to LockBit Ransomware](https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/)
    * [DFIR Labs](https://thedfirreport.com/)
    * [CHAES:Novel Malware Targeting Latin American E-Commerce](https://www.cybereason.com/hubfs/dam/collateral/reports/11-2020-Chaes-e-commerce-malware-research.pdf)
- Example Global Incident Response Reports
    * [PaloAlto Unit 42](https://www.paloaltonetworks.com/engage/unit42-2025-global-incident-response-report)

## Cyber Kill Chain
### Summary
- Cyber Kill Chain refers to the attack lifecycle and consists of seven different stages, as shown below.
![Cyber Kill Chain Graphic](../images/Cyber_kill_chain.png)

**Stages of the Cyber Kill Chain**
- Recon - Attacker chooses target and performs information gathering(`OSINT`) to become familiar with the target.
- Weaponize - Initial Access malware developed and embedded into some exploit or deliverable payload.
- Exploit - Moment when an exploit or payload is triggered. Code Execution to gain access or control
- Installation - initial stager is executed and running on the compormised machine.
- Command & Control - Attacker establishes remote access to the compromised machine.
- Action - Attacker carries out it's objectives.
> This may not be a linear process as the graphic suggests. Some of these steps may need to be repeated to establish the next phase.

**MITRE ATT&CK Framework**
- More granular, matrix-based knowledge base of adversary tactics and techniques used to achieve specific goals.
- A `tactic` is a high-level adversary objective during an intrusion. Basically, what they want to achieve at this stage of the kill chain.
    * Initial Access
    * Persistence
    * Privilege Escalation
- `Techniques` are methods adversaries use to achieve a tactic.
- Techniques have ID's
    * `T1105 Ingress Tool Transfer` - Refers to the tools attackers use to download a tool, think `wget` and `curl`
    * `T1021 Remote SErvices` - Refers to adversaries using proctocols like RDP, SSH, or SMB for lateral movement.
- Sub-techniques are children of techniques that capture a particular implementation
    * `T1003.001 - OS Credentials: LSASS Memory` - Refers to attackers dumping credentials from LSASS process memory
    * `T1021.002 - Remote Services: SMB/Windows Admin Shares` - Refers to attackers interacting with shares using valid credentials  

**MITRE Pyramid of Pain**
- Illustrates how much effor it takes for an adversary to change tactics.
![MITRE Pyarmid of Pain](../images/ir_mitre.png)

**MITRE ATT&CK integration in TheHive**
- `TheHive` si a case management platform designed for cybersecurity teams to efficiently handle incidents by process alerts

**MITRE ATT&CK Mapping Example**
|Tactic|Technique|ID|Description|
|------|---------|--|-----------|
|`Initial Access`|Exploit Public-Facing Application|T1190|Confluence CVE exploited|
|`Execution`|Command and Scripting Interpreter: PowerShell|T1059.001|PowerShell used for payload download|
|`Persistence`|Windows Service|T1543.003|Windows Service for persistence|
|`Credential Access`|LSASS Memory Dumping|T1003.001|Extracted credentials|
|`Lateral Movement`|Remote Desktop Protocol|T1021.001|RDP lateral movement|
|`Impact`|Data Encrypted for Impact|T1486|LockBit ransomware|

# The Incident Handling Process

# Incident Analysis and Response

# Todo

