# SQL Injection Fundamentals

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

