# Initial Enumeration
## System Enumeration
- System Info
```
# Linux Kernel Version
uname -a
cat /proc/version
cat /etc/issue

# Linux Arch and CPU info
lscpu
```
- Running processes
```
ps aux

# Processes running as root
ps aux | grep root
```

## User Enumeration
Who are we? What permissions do we have? What are we capable of doing?
```
whoami

# What groups am I in
id

# What can I run as sudo?
sudo -l
```
- Check for access to sensitive files
```
cat /etc/passwd

# Maybe passwords
cat /etc/shadow

# Groups
cat /etc/group
```
- Check users history
```
history
```

## Network Enumeration
- Network config
```
ifconfig

# old
ip a
```
- routes
```
ip route

# old
route
```
- arp tables
```
ip neigh

# old
arp -a
```
- Open Ports
```
netstat -ano
```

## Password Hunting
```
# Quick and dirty but color coordinated...
grep --color=auto -rnw '/' -ie "[search term] --color=always 2> /dev/null

# Find a word in a file name
locate [search term] | more

# Locate SSH Keys
find / -name id_rsa 2> /dev/null
find / -name authorized_keys 2> /dev/null
```

# Exploring Automated Tools
## LinPEAS
```
./linpeas.sh

# Look for the red and yellow
```

## LinEnum
Basically the same as linpeas

## Linux-Exploit-Suggester
```
./linux-exploit_suggester.sh

```
## LinuxPrivChecker.py

# Escalation Path: Kernel Exploits
Basically google search for the version of your distribution (uname -a) and download and possibly compile the exploit. Normally we are looking for `Privilege Escalation` or `RCE`.     
```
# Automated
./linux-exploit-suggester.py
```

# Escalation Path: Passwords & File Permissions
## Stored Passwords
> Look at [PayloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/#files-containing-passwords)  

- Bash/zsh History
```
# history command
history

# Cat the history
cat .bash_history
```
- Searching the local directory
```
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```
- Old passwords in /etc/security/opasswd
```
cat /etc/security/opasswd
```
## Weak File Permissions
Do we have access to a file we shouldn't be able to access as a normal user?
- Check file permissions /etc/passwd and /etc/shadow
```
# Check permissions on /etc/passwd /etc/shadow
ls -la /etc/passwd
ls -la /etc/passwd

# Using unshadow to combine passwd and shadow
unshadow passwd shadow
# After combining the two files, we can delete users who don't have a hash, save that to another file, and run it through hashcat.
```
  If `/etc/passwd` or `/etc/shadow` are modifiable, we can escalate by changing the password or changing group membership

## SSH Keys

# Escalation Path: Sudo

# Escalation Path: SUID

# Escalation Path: Other SUID Escalation

# Escalation Path: Capabilities

# Escalation Path: Scheduled Tasks

# Escalation Path: NFS Root Squashing

# Escalation Path: Docker

# todo
- [ ] Continue on Escalation Path: Passwords & File Permissions
- [ ] Get links for linpeas, linenum, linux-exploit-suggester
- [ ] Add a table at the top of all the tools used.
- [ ] Test
