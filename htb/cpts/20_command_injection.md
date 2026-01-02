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
> Note: We should always try our final command on our local machine to make sure it works

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
|Sub-Shell|``` `` ```|`%60%60`|Both (Linux-only)|
|Sub-Shell|`$()`|`%24%28%29`|Both (Linux-only)|

*Table of Command Injection Methods*
> Note: Any of the above CI Methods should work on any web framework, with the exection of the semicolon `;`. The semicolon will not work in windows command line, but will work in powershell.

To perform the injection, we would write out the expected input (in this case an IP), add one of our methods, and then add thee command we would like to run.
Example: 127.0.0.1\n whoami

## Injecting Commands
If our attempt to inject a command fails, we need to determine where the input sanitization is happening. The easiest way to do this is through Developer tools.

We can open firefox developer tools with `CTRL-SHIFT-E` and observe the network tab to see if our request is even sent or if the front-end blocked it. If no request is sent (nothing appears in the network tab) then the front-end is doing the input sanitazation. 

### Bypassing Front-End Validation
The easiest way to bypass the front end is to send the request manually using a proxy like burp.
- First we capture a standard request. In this case, just an IP
- Then we tack our payload on to the end of the of the parameter we're trying to inject on.
    >Note: We may need to URL-Encode any spaces or special characters  

Another way may be to review the source code. In our IP address example, we can look at the source code and see what characters are allowed and what pattern they follow. 
```html
<body>
  <div class="main">
    <h1>Host Checker</h1>

    <form method="post" action="">
      <label>Enter an IP Address</label>
      <input type="text" name="ip" placeholder="127.0.0.1" pattern="^((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$">
      <button type="submit">Check</button>
    </form>
```
*Sample input validation*

In the above, we can see the `pattern` that is allowed in this particular web app.

## Other Injection Operators
### AND (&&) Operator
The AND operator requires that both commands are successful. 
Eample: If we try and just use the AND operator without an IP (Payload = `ip=%26%26+whoami`), then both will fail because the `ping` command will exit code 1, meaning it errored out, and our additional command will not process.

### OR (||) Operator
The OR operator only executes if our first command fails to execute.
Example: If we use the same example as above, and just swap the `&&` for `||`, we'll see the command succeed, because the first command (ping) errored out, and the second command can run. However, if the first command had not errored out and exited code 0, our command would not have run, because the first command completed successfully.

# Filter Evasion
## Identifying filters
### Filter/WAF Detection
- If an error message is displayed on a different page (a redirect), with information like ouir IP and our request, we were probably denied by WAF.

### Blacklisted Characters
```PHP
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```
*Example PHP code for with blacklisted characters*

Referencing the above code, if our string contains any of the characters in `$blacklist`, we'll be denied.

- The easiest way to evaluate the blacklist (if we can't see the code), is to append each character to a valid input and see what get's blocked and what doesn't.

## Bypassing Space Filters
### Bypass Blacklisted Spaces
- Spaces are a commonly blacklisted character
- Use Tabs (`%09`)
- Use $IFS (Linux Only)
    - `ip=127.0.0.1%0a${IFS}`
    - Linux only
- Use Brace Expansion (Bash Only)
    - `{ls,-la}`
> Note: More bypass at [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)

## Bypassing Other Blacklisted Characters
## Bypassing Blacklisted Commands
## Advanced Command Obfuscation
## Evasion Tools

# Prevention

# Todo
- [ ] Pickup at Filter Evasion
