---
description: >-
  ffuf provide us with a handy automated way to fuzz the web application's
  individual components or a web page.
---

# Fuzzing

### FFUF

```bash
# Directories
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/FUZZ

# Extenions 
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/index.FUZZ

# Pages 
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/FUZZ.php

# Recursive 
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/FUZZ -recursion -recursion-depth 1 -e .php -v

# Subdomains
ffuf -w wordlist.txt:FUZZ -u http://FUZZ.url.com:8000

# Virtual hosts
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000 -H "Host: FUZZ.url.com"

# Parameters GET
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/test/test.php?FUZZ=key

# Parameters POST
ffuf -w wordlist.txt:FUZZ -u http://url.com:8000/test/test.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' 
```

### Request

```bash
# Replace any value in the burp request with FUZZ
ffuf -request /path/file -request-proto http -w /path/wordlist
```
