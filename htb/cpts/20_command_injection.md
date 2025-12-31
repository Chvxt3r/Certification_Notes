# Intro
 Injection occurs when user-controlled input is misinterpreted as part of the web query or code being executed, which may lead to subverting the intended outcome of the query to a different outcome that is useful to the attacker.

The user input we control must directly or indirectly go into (or somehow affect) a web query that executes system commands directly on the back-end server.

## PHP Example
PHP may use the `exec`, `system`, `shell_exec`, `passthru`, or `popen to execute commands on the back-end server, each with a different use case.

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```
*Example PHP Code*

The above code is a web app that allows a user to create a PDF on the back-end servers file system in the `/tmp` directory with a filename supplied by the user. Because the `filename` parameter gets passed directly to the `touch` command, this would be vulnerable to a command injection.

## NodeJS Example
In NodeJS, the developer may use the `child_process.exec` or `child_process.spawn` for the same purpose as the PHP example.

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```
*This NodeJS snippet performs a similar function to the PHP above*

The above NodeJS is vulnerable because it again uses the filename parameter with the `touch` command without sanitizing it first.

# Exploitation
## Detection
The Process for detecting OS command injection is the same as the process for exploiting it. We attempt to append our malicious command through various methods.

### Example Host Checker App
Below we see a sample host checker app that asks for an IP address to verify whether the host is up or not.
![cmdinj_basic_exercise_1](./images/cmdinj_basic_exercise_1.jpg)

If we enter the loopback IP (127.0.0.1), we can see that it returns the output of the `ping` command.
![cmdinj_basic_exercise_2](./images/cmdinj_basic_exercise_2.jpg)

Without access to the source code, we can assume that the app is taking our input (the IP) and passing it directly to a system level ping command. That ping command probably looks something like this:
```bash
ping -c 1 OUR_INPUT
```
If the input is not sanitized and escaped before it used with the ping command, we may be able to inject a malicious command.

### Command Injection Methods
|Injection Operator|Injection Character|URL-Encoded Character|Executed Command|
|------------------|-------------------|---------------------|----------------|
|Semicolon|`;`|`%3b`|Both|
|New Line|`\n`|`%0a`|Both|
|Background|`&`|`%26`|Both (second output generally shown first)|
|Pipe|`\|`|`%7c`|Both (only second output is shown)|
|AND|`&&`|`%26%26`|Both (only if first succeeds)|
|OR|`\|\|`|`%7c%7c`|Second (only if first fails)|
|Sub-Shell|`\```|`%60%60`|Both (Linux-only)|
|Sub-Shell|`$()`|`%24%28%29`|Both (Linux-only)|

*Table of Command Injection Methods*

## Injecting Commands
## Other Injection Operators

# Filter Evasion
## Identifying filters
## Bypassing Space Filters
## Bypassing Other Blacklisted Characters
## Bypassing Blacklisted Commands
## Advanced Command Obfuscation
## Evasion Tools

# Prevention
