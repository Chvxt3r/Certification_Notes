# Common
Connect to a database
```bash
mysql -u root -h host.example.com -P 3306 -p
```

View a list of databases
```sql
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

Use a specific database
```sql
mysql> USE users;
```

Show all tables within a DB
```sql
mysql> SHOW TABLES;
```

Describe table (Shows valid data types)
```sql
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

# Study Notes
## Intro to MySQL
### Structured Query Language
- Required to follow the [ISO Standard](https://en.wikipedia.org/wiki/ISO/IEC_9075)

### Command Line
- `mysql` utility is used to authenticate and interact with MySQL/MariaDB databases

```bash
# sign-in
mysql -u root -p
```
> Leaving the `-p` blank will prompt for a password, usually the easiest way and also avoids the password being kept in logs and command history

- Not specifying a host will automatically try to connect to `localhost`. Host can be specified with the `-h` flag. Port can be specified with the `-P` flag.

```bash
mysql -u root -h host.example.com -P 3306 -p
```
> Note: the default MySQL/MariaDB port is 3306

### Creating a database
- Once logged in, we can interact with the service
> Note: MySQL expects commands to be terminated with a semi-colon `;`

```bash
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
```

- We can view a list of databases using `SHOW DATABASES` and we can work with that db using the `USE` command

```bash
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```
### Tables
- Databases store information in tables. Tables consist of rows and columns (Like a spreadsheet) and the intersection of these are called cells (also like a spreadsheet)
- Tables are created with a fixed number of columns, where each column is a particular data type.
- Command data types include: `numbers`, `strings`, `date`, `time`, and `binary data`
- We use the `CREATE TABLE` command to create a new Table

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

- We can obtain a list of current tables using the `SHOW TABLES` statement
- We can use the `DESCRIBE` statement.

```bash
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

#### Table Properties
- Within `CREATE TABLE`, we can assign properties.`AUTO_INCREMENT` and `NOT NULL` are often used in `id` fields. `AUTO_INCREMENT` automatically increments the `id` cell every time a new record is created. `NOT NULL` specifies that this field can not be blank (Required Field).

Common Properties
|Property|Description|
|########|###########|
|`AUTO_INCREMENT`|Automatically increments the field|
|`NOT NULL`|This cell cannot be empty (Required Field|
|`UNIQUE`|Ensures that this cell is unique. Usefull for usernames|
|`DEFAULT`|Specifies a default value. Usefull for join dates, etc. ```sql date_of_joining DATETIME DEFAULT NOW(), ```|
|`PRIMARY KEY`|Uniquely identifies each record in the table|

Example `CREATE TABLE` query:
```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

### SQL Statements
#### Insert
Used to add new records to a give table
Syntax:
```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```
Example (Adds a new login to the `logins` table):
```sql
mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');

Query OK, 1 row affected (0.00 sec)
```
>:warning: Skipping columns with the `NOT NULL` constraint will result in an error (Required Value). The above example requires the user to fill in values for all the columns present in the table

Syntax (Skipping columns with default values)
```sql
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```
Example:
```sql
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');

Query OK, 1 row affected (0.00 sec)
```
> The above example inserts a username and password pair while skipping `id` and `date of joining` columns.

Insert multiple records by separating the values with a comma:
```sql
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');

Query OK, 2 rows affected (0.00 sec)
Records: 2  Duplicates: 0  Warnings: 0
```
> The above example inserts 2 new records, with values separated by a comma


#### Select
#### Drop
#### Alter
#### Update
