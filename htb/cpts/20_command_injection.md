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
