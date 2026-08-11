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
In-Band - Output of both the intended and the new query printed directly on the front-end and can be directly read.
    Union Based - have to specify the exact location (such as a column), which we can read, so the query will direct the output there.
    Error Based - Used when we can see SQL errors on the front end, so we intentionally cause an error that returns the output we need.
Blind - Output not printed and must be retrieved, character by character.
    Boolean Based - Use SQL conditional statements to control whether the page returns any output at all if our conditional statement returns true
    Time Based - Use SQL conditional statements to delay the page response if the conditional statement returns true using the `Sleep()` function
Out-of-band - No access to the output whatsoever. Must use a proxy to read the data. i.e., DNS Record
