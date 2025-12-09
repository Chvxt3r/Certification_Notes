# Intro

# HTTP Verb Tampering
## Intro
### Verbs
HTTP has 9 different verbs that can be accepted as HTTP methods  

Commonly Used Verbs, other than `GET` and `POST`:
|Verb|Description|
|----|-----------|
|`HEAD`|Identical to a `GET` request, but its response only contains the headers, without the response body|
|`PUT`|Writes the request payload to the specified location|
|`DELETE`|Deletes the resource at the specified location|
|`OPTIONS`|Shows different options accepted by a web server, like accepted HTTP verbs|
|`PATCH`|Apply partial modifications to the resource at the specified location|

### Insecure Configurations
Example config:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```
In the above, even though the admin limits `GET` and `POST` to valid users, you may be able to use another method (like `HEAD`) to get the same result.

### Insecure Coding
Example Code:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
In the above example, the sanitization check is only being performed on the `GET` request `if(preg_match($pattern, $_GET["code"])) {`. However, the actual query (`$query`) is built using the `$_REQUEST["code"]` parameters. This will allow a `POST` request to bypass the sanitization check. 

## Bypassing Basic Authentication
## Bypassing Security Filters

# Insecure Direct Object Reference (IDOR)
## Identifying IDOR
## Mass IDOR Enumeration
## Bypassing Encoded References
## IDOR in Insecure APIs
## Chaining IDOR Vulnerabilities

# XML External Entity (XXE) Injection
## Local file Disclosure
## Advanced File Disclosure
## Blind Data Exfiltration

