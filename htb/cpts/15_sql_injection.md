# Definition
Occures when user-input is used in a SQL query string without properly santizing or filtering the input

## Example
Consider the following PHP
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

Anything entered into `%searchInput` becomes the search, and the resulting sql query will look something like:
```sql
select * from logins where username like `%$testinput`
```

If we try and add some sql code in the search field, it just becomes the search term, for example if we enter `SHOW DATABASES;` in the search field, we get the resulting SQL:
```sql
select * from logins where username like `%SHOW DATABASES;`
```

Obviously this will return few results.

In this particular example, since there's no sanitization in place, we can terminate the sql statement and append a new one, by simply using a `'`

For example, we can enter `1'; SHOW DATABASES;'

Resulting in the following SQL query:
```sql
select * from logins where username like '%1'; SHOW DATABASES;'
```

and Waalaa, we have an injection

# Types of SQL Injections
 Based on how and where we retrieve their output.
 ![types of injections](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/33/types_of_sqli.jpg)

## Definitions
* In-Band - Output of both the intended and the new query printed directly on the front-end and can be directly read.  
    ** Union Based - have to specify the exact location (such as a column), which we can read, so the query will direct the output there.  
    ** Error Based - Used when we can see SQL errors on the front end, so we intentionally cause an error that returns the output we need.  
* Blind - Output not printed and must be retrieved, character by character.  
    ** Boolean Based - Use SQL conditional statements to control whether the page returns any output at all if our conditional statement returns true  
    ** Time Based - Use SQL conditional statements to delay the page response if the conditional statement returns true using the `Sleep()` function  
* Out-of-band - No access to the output whatsoever. Must use a proxy to read the data. i.e., DNS Record  
    **  

# Query Logic Subversion
## Auth Bypass
In auth bypass, the trick is the `WHERE` conditions interaction with `AND` and `OR`. With the `AND` condition both statements must be true, but with the `OR` condition, only one statement needs to be true.

Consider a type unsanitized query for authentication
```sql
SELECT * FROM logins WHERE username='admin' AND password='password';
```

This query uses the `AND` operator to match the given username and password. If the DB returns matched records, the credentials are valid, and would evaluate to `true`, if we were to submit the wrong password, the `AND` operator would evaluate to false, and the login would fail.
> This is all about getting the webpage to evaluate the login credentials as `true`

## SQLi Discovery
To verify if the page is even vulnerable to injection, try inserting one of the below characters and see if the page changes.
|Payload|URL Encoded|
|-------|-----------|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3b`|
|`)`|`%29`|
> Note: Sometimes we'll need to use the url encoded form.

In our example above, injecting a single quote throws a syntax error, because we have an odd number of quotes in our query.

## OR Injection
* Most Important: We always need the query to return `true`, regardless of the username and password entered
* Critical to this, is the MySQL Operation Precedenct, which states an `AND` is always evaluated before an `OR`. This means that if there is at least one `true` condition along with an `OR` operator, the condition will evaluate to true.

Our original query:
```sql
SELECT * FROM logins WHERE username='admin' AND password='password';
```

If we can modifiy our query to contain at lease one `true` statement and an `OR` operator, we can bypass the auth.

True statement: `'1' = '1'`

So let's modify our query:
```sql
SELECT * FROM logins WHERE username='admin or '1'='1'' AND password='something';
```
:warning The above query fails with a syntax error, because too many quotes.

So our username entry needs to look like `admin or '1'='1` to preserve the original quotes, resulting in:
```sql
SELECT * FROM logins WHERE username='admin or '1'=1' AND password='something';
```
Query in plain english:
* if username is `admin` `OR` if `1=1` return `true` `AND` if password is `something`

Why this works:
`AND` is evaluated first:
* `'1'='1' is `TRUE`
* `PASSWORD='something'` is `FALSE`
* The result of the `AND` condition is `FALSE` because `true AND false` is `False`

Next, the `OR` is evaulated:
* If `username='admin'` exists, the entire query returns true
* `'1'='1'` condition is irrelevant in this example because we just needed to get the `OR` in there.
> we just need at least part of the `OR` to evaulate to `True`

### Additional Resources
![Infosec Mastery](https://www.youtube.com/watch?v=zEWQD4OwGZs)
