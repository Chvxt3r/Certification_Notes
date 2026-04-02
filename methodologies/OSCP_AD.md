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



### Credits
[Got Root?](https://infosecwriteups.com/how-i-attacked-active-directory-during-oscp-labs-and-what-tools-actually-worked-8a10e12930a4)
